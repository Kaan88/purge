# M3-R2 review: waves 3 to 5 (broker core, consent, flow, exec, undo, purge, UI client, runner)

Date 2026-11-22. Reviewer: Fable (M3-R2). Branch `baseline`, diff `bfde762..86ef0ae`.
While this review was being written `baseline` moved to ba1394d (`m3-glue`: the medium route records the uninstall
window, the UI sends `outcome`). That change is reviewed under flagged point 7 and finding M3; line numbers of
`bins/purge-broker/src/uninstall.rs` are those of ba1394d, every other line number is the same in both commits.

Read-only review: no source changed, nothing committed. Two things were run on the host:

- `cargo test -p purge-broker --lib` (result in "What was run").
- One experiment outside the repo (`%TEMP%\opencode\pipe-sync-test.ps1`): a named pipe opened with exactly the
  `CreateFileW` flags of `BrokerLauncher.ConnectAsync`, one thread blocked in a read, a second thread writing.
  It is the evidence for finding B2.

Nothing was run elevated, on a VM, or against the real broker.

Read in full: `bins/purge-broker/src` `serve.rs`, `session.rs`, `start.rs`, `main.rs`, `wire.rs`, `uninstall.rs`,
`scan.rs`, `plan.rs`, `execute.rs`, `exec_live.rs`, `broker.rs`, `purge.rs`, `undo.rs`, `recover.rs`,
`history.rs`, `backend.rs`, `live.rs`, `consent/view.rs`, `consent/dialog.rs`, `consent/text.rs` (production
part), `lifetime.rs` (`Closer`); `bins/purge-engine/src/stdio/uninstall.rs` (production part), `pipeline.rs`
(`route`, `uninstall_commands`, `uninstall_in`); the diffs of `purge-exec` `execute.rs`, `plan_in.rs`,
`recover.rs`, `undo.rs`, `review.rs`, of `purge-win` `taskdialog.rs` and `os.rs`, of `purge-inventory`
`runner.rs`, of `purge-rpc` `methods.rs`; `purge-exec` `expiry.rs` (`Categories`, the head of `purge`),
`locked.rs` (`reconcile`); `purge-plan` `collapse.rs` (rules, `nests_in`, absorb); `purge-guard` `prefix.rs`,
`live.rs` (`check_protected_descendants`); `purge-source` `live/system.rs` (`interactive_env`, `apply_block`);
`purge-win` `sid.rs` (`is_admin_only_writable`), `process.rs` (`JobProcess::spawn`);
`ui/Purge.Client/Broker/BrokerLauncher.cs`, `BrokerServerCheck.cs`, `BrokerRpcClient.cs`, and
`Pipeline/UninstallPipeline.cs` (`BrokerUninstallClient`). The seven writer notes, the design's threat table
(section 4) and invariants B1 to B11.

Not read: `bins/purge-engine/src/stdio.rs` beyond its use of the uninstall handlers, `stdio/icons.rs`,
`purge-win/src/icons.rs`, `live_host.rs`, `args.rs`, `link.rs`, `baseline.rs`, `testkit.rs`, the test modules
(test names are cited from the writer notes, the bodies were not checked, except the `observed` tests of
`flow_tests.rs`), `purge-exec` `execute.rs` `drive` and the M2 act-time gates, the `Purge.App` views.
A claim that rests on Windows behaviour I know from reading and did not run says so.

Labels: B blocker, M must be fixed before the `m3-broker` gate, S should be fixed, N note.

## Verdict

- **Two B findings.**
  - B1: the broker expands the uninstall command of a machine-scope program with the user's own
    `HKCU\Environment` and runs the result elevated; the runner then expands it a second time.
  - B2: the UI cannot talk to the real broker. The pipe handle is synchronous, the reader thread is always inside
    a read, and every write waits for that read. `engine.hello` is never sent. Shown by experiment.
- **Four M findings**: `uninstall.run` has no broker dialog although B4 and T2 say every change has one (M1); the
  route judges only the executable, not what an interpreter is told to load (M2); `uninstall.observed` raises a
  failed broker run to `post` (M3); user data below a ticked parent is neither named as user data in the dialog
  nor given its own purge dialog (M4).
- Seven S findings, nine notes.
- The core of the attack list holds: one frozen `BoundPlan` is drawn and run, ids only, a plan id works once, a
  declined or lost dialog changes nothing, an approved run finishes without its client, names are escaped.

Counts: B 2, M 4, S 7, N 9.

## Findings

### B1. A machine-scope uninstall command is expanded with the user's environment and run elevated

`bins/purge-broker/src/uninstall.rs:531` reads `sources.sys.env()`, and lines 542-543 give it to
`pipeline::route` and `pipeline::uninstall_commands`. `LiveSystem::env`
(`crates/purge-source/src/live/system.rs:461-464`) is `interactive_env`, which ends with
`apply_block(.., "HKU\<sid>\Environment", true)` (line 217) and the volatile block. `apply_block` (lines 99-133)
inserts every value under its upper-cased name, so a value in `HKCU\Environment` replaces `PROGRAMFILES`,
`PROGRAMDATA`, `SYSTEMROOT`, `WINDIR`, `COMMONPROGRAMFILES` and any other name. `uninstall_commands`
(`bins/purge-engine/src/pipeline.rs:699-724`) expands both the executable and the arguments with that map.
`route` (`pipeline.rs:735-766`) then judges only the expanded executable.

Second expansion: `run_uninstall` (`crates/purge-inventory/src/runner.rs:394-398`) calls `.expand(&env)` on the
command even when the caller passed `req.command`. The command `prepare` froze is therefore expanded again, at
run time, with the environment as it is then.

Attack. A medium process of the same user (no client access needed, a registry write is enough):

1. Find an HKLM Uninstall entry whose command has an absolute, admin-only executable and a `%NAME%` reference in
   its arguments. Shapes that exist: `C:\Windows\System32\cmd.exe /c "%ProgramData%\Vendor\uninstall.cmd"`,
   `"C:\Windows\System32\rundll32.exe" "%ProgramFiles%\Vendor\un.dll",Uninstall`,
   `%windir%\system32\sdbinst.exe -u "%ProgramData%\..."`, a full-path `msiexec` with a package path.
2. Write `HKCU\Environment\ProgramData = C:\Users\me\x` (or the name the entry uses) and plant the file.
3. Wait for the user to uninstall that program with Purge. `prepare` expands the arguments to the planted path,
   the executable is still admin-only, the route is `Broker`, and `uninstall.run` starts it elevated.

Variant through the second expansion: a reference that is undefined at `prepare` stays `%X%` in the frozen
command; defining `X` in `HKCU\Environment` between `prepare` and `run` changes the arguments after the command
was shown and after the route was decided. "The command shown is the command run" (broker-flow choice 1) does not
hold for such a command.

This is T9 and B7 ("Purge is never an elevation vehicle") and the rule of B6 and T7 ("no directory from the
environment in an elevated process") applied to the command line. It needs a matching installed program, so it is
not reachable on every machine; where it is, the result is code of the attacker's choice at high integrity with
no prompt that names it.

Fix:

1. In the broker, expand a machine-scope command with the machine environment only (`machine_env`: the values
   Windows derives plus `HKLM\...\Session Manager\Environment`). Add `SystemSource::machine_env` or pass a flag.
2. In `route`, expand the command twice, once with the machine map and once with the user's. If any part of
   either command differs, the route is `Medium`. A reference that neither map defines is also `Medium`.
3. In `run_uninstall`, do not expand a command given in `req.command`; it is already the string that was shown.
4. Tests: an HKLM entry with `%ProgramData%` in its arguments and a user override is `Medium`; a frozen command
   holding `%X%` is started with `%X%` unchanged.

### B2. The UI's pipe client blocks every write behind its own reader: `engine.hello` is never sent

`ui/Purge.Client/Broker/BrokerLauncher.cs:216-217` opens the pipe with
`FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, without `FILE_FLAG_OVERLAPPED`, and
line 229 wraps it in `new FileStream(pipe, FileAccess.ReadWrite, 64 * 1024, isAsync: false)`.
`BrokerRpcClient`'s constructor (`BrokerRpcClient.cs:58`) starts the reader thread, which blocks in `ReadLine`.
Requests are written from other threads (`WriteLineLocked`, lines 178-186).

Windows serialises all I/O on a synchronous file object. A `WriteFile` on the handle waits until the pending
`ReadFile` on the same handle returns.

Experiment (this laptop, same flags, same shape): the client thread blocked in a read; a write of three bytes
from a second thread had not returned after 3 s; it returned as soon as the server wrote one byte.

Failure against the real broker:

1. `LaunchAsync` returns a session whose reader is already blocked in a read.
2. `HelloAsync` writes; the write waits for the read.
3. The broker has sent nothing and waits for `engine.hello`. After `HELLO_WAIT` (30 s) it refuses the client
   (`serve.rs:451-452`) and disconnects.
4. The UI reports "The administrator part ended."

After a hello that wins the race, every later request waits until the broker happens to send a line. The
in-process tests do not show this because they do not use one synchronous duplex handle. Nothing unsafe follows:
no request arrives, so nothing runs. It does mean no flow through the UI can work.

`FileStream` is also not safe for a read and a write at the same time on two threads (one shared buffer).

Fix: open with `FILE_FLAG_OVERLAPPED` (keep the SQOS flags) and wrap the handle in
`new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle)`; that stream
supports one reader and one writer at once. `BrokerServerCheck` needs no change. Add a test that serves a real
named pipe, lets the reader block, and requires `HelloAsync` to finish in under a second.

### M1. `uninstall.run` runs an elevated uninstaller with no broker dialog

`uninstall.rs:748-809`; `crates/purge-rpc/src/table.rs:122` (`Execute`, `consent: false`).

Invariant B4 says every mutating request ends in a TaskDialog shown by the broker. T2 says of an accepted client
"every change still ends in the dialog", and T11 says "the consent dialog, not UAC, is the approval". T14 accepts
that a same-user process can inject into `Purge.exe` because "T1, T3, T4 still hold".

They do not hold for `uninstall.run`. A client that passed the peer check can send `uninstall.prepare` for any
machine-scope program and then `uninstall.run {quiet: true}`. The broker starts that program's quiet uninstaller
elevated. The user approved one UAC prompt for `purge-broker.exe`, perhaps for another program; the only confirm
dialog is drawn by the medium UI, which is the process under attack. Without Purge the same attacker would need a
UAC prompt that names the uninstaller.

Fix, one of:

1. A broker dialog for `uninstall.run`, drawn from the session: program name, the exact command line, the signer,
   quiet or not. It replaces the UI's confirm step for broker-route programs, so the user still answers once.
2. A DECISIONS row that says UAC plus the UI's confirm is the approval of `uninstall.run`, with B4, T2, T11 and
   T14 reworded to except it.

I recommend 1. It is one more `view` variant and it closes the only mutating request that changes the machine
without the broker asking.

### M2. The route judges the executable only: an admin-only interpreter makes any script broker-route

`pipeline.rs:744-765`. A machine-scope entry is `Broker` when every command's `exe` is admin-only writable. The
arguments are not looked at. With `cmd.exe /c <script>`, `rundll32.exe <dll>,<fn>`, `wscript`, `cscript`,
`powershell -File`, `mshta`, `regsvr32`, `msiexec /x <path>.msi` or `java -jar`, the executable is in System32
and the file that decides what runs may be user-writable (a vendor folder under `ProgramData` with inherited
`Users: create files`, a per-user path written by a machine-wide installer).

Attack: replace that script or DLL as a medium process; the next uninstall of the program through Purge runs it
elevated. This is T9 without any environment variable.

Fix: in `route`, for a known host executable (a fixed list of file names under the Windows directory), find the
file it is told to load and require it to be admin-only writable too; when it cannot be found, the route is
`Medium`. An absolute path anywhere in the arguments that exists and is user-writable also gives `Medium`.

### M3. `uninstall.observed` raises a failed broker run to `post`

`uninstall.rs:821-857`. `observed` accepts a session of any route and ends with
`session.set_ran(reported_ok && verify.is_passed())` (line 849). `set_ran` overwrites `uninstaller_ok`.

Attack: `uninstall.run` on a broker-route session fails (`uninstall_failed`, `uninstaller_ok = false`), but the
program is gone. The client then sends `uninstall.observed {session_id}` with no `outcome`. Verify-gone passes,
`uninstaller_ok` becomes true, the window is already in the fingerprint from the run (the new code keeps
`t_start` and moves `t_end`), and `leftovers.scan` answers `post` with the Safe items preselected.

That breaks broker-flow choice 3 ("there is no way to raise a mode") and the rule tested by
`a_failed_uninstaller_is_forced_even_when_the_program_is_gone`. Preselected Safe items are not attention entries
in the dialog, so the user is shown less than after a failed uninstall should be shown.

Fix:

1. `observed` answers `wrong_route` unless `session.route == Route::Medium`.
2. A session that already ran is never raised: `uninstaller_ok` may go from true to false only.
3. Test: failed `run`, then `observed`, then a scan that is `forced` with nothing preselected.

### M4. User data below a ticked parent has no "user data" line in the dialog and no purge dialog of its own

Three places agree only for absorbed children:

- `collapse` gives a parent `UnmatchedChildren` and keeps a user-data descendant as an item of its own; such a
  parent "never absorbs" (`crates/purge-plan/src/collapse.rs:39-41`, 148-158). The user may tick the parent alone.
- `check_protected_descendants` (`crates/purge-guard/src/live.rs:1053-1081`) refuses only a Blocked or
  hard-blocked descendant. `UserData` is a soft blocker, so the plan binds.
- The consent view lists what goes with an item from `plan.children` only
  (`bins/purge-broker/src/consent/view.rs:546-560`, 594-626): the absorbed ones. A top-level candidate that lies
  inside the ticked parent is not looked at. The parent's line says "ticked by you", not "user data", and the
  item inside is not listed.
- `expiry::Categories::read` (`crates/purge-exec/src/expiry.rs:969-979`) marks a parent as user data when it or
  one of its `children` is. Same gap. Thirty days later the parent's quarantine item is in the bulk purge dialog.

Result: a folder that holds an item the scan classed as user data can be quarantined with a dialog that never
says so, and purged for good without the one-item dialog DECISIONS 2026-11-16 requires. That is the attack "purge
a user-data item without its own dialog". Found by reading; not reproduced on a fixture. Where the scanner puts
`Blocker::UserData` on the parent itself (`fs_installdir`) the purge side is covered, the dialog side is not
(the view tests `category`, not the blocker).

Fix: one helper, "the candidates of the scan document, top-level or absorbed, that nest in this whole-tree item",
used by both. In the view each of them with `Category::UserData` or `Blocker::UserData` becomes a "Taken with its
parent" attention entry and the parent gets `Reason::UserData`. In `Categories` the parent is user data when any
of them is. Tests: a Likely parent with a user-data item inside, parent ticked alone; the dialog names both, the
purge asks for it alone.

### S1. The supervisor can block for ever on its own event channel

`serve.rs:564` makes `sync_channel(256)`; `Shared::mark_broken` (269-271) does a blocking `send`, and it is
reached from `respond` (273-283) on the supervisor thread, which is the channel's only receiver.

Failure: a client sends more than 256 lines and stops reading. The supervisor's inline write times out after
30 s, `mark_broken` sends into a full channel, and the supervisor never returns. The reader thread is blocked in
its own `send` too. The elevated process then stays: no idle exit, no parent check, no pipe-loss handling. Only
the checked client can do it, and nothing runs, but T13 says a stalled pipe ends the broker.

Fix: `try_send` in `mark_broken` and an `AtomicBool` the supervisor reads each tick; or an unbounded channel for
the two control events.

### S2. A run spends one scan, not the program: a sibling scan can be planned and run afterwards

`execute.rs:153-163` keeps the claim of the plan's scan after a run and removes the session. Other scans of the
same session (made before the run), and every scan from a stored fingerprint, stay in the table with no claim.
`plan.create` on one of them succeeds (`plan.rs:106-108` checks only the scan id) and `plan.execute` runs it.

Effect: a second run over a document that describes the machine before the first run. The act-time gates see the
items gone, so I expect `Vanished` results, not damage; it is still the case exec.md's first contract excludes
("a second plan from it would be a second run of the same items").

Fix: when a run starts, mark every scan of the same program id as spent (one flag on `Scan`, checked by
`plan.create`), and refuse `plan.create` for a scan whose session is no longer in the table.

### S3. `quarantine.purge` with every dialog declined answers `Ok` and ends the broker

`purge.rs:313-320`: when no unit was approved the result is `Ok {outcome: partial, purged: 0}`.
`serve.rs:906` counts an `Ok` of `quarantine.purge` as a completed change, so the broker drains and exits
although nothing was changed, and the client is not told `consent_declined`. Fix under flagged point 3.

### S4. The uninstaller inherits the broker's environment and working directory

`runner.rs:534-541` (`current_dir: None`) and `crates/purge-win/src/process.rs:378-389` (`lpEnvironment` null).
The broker's environment is the user's (built from `HKCU\Environment` at elevation), and `main.rs` never sets a
working directory, so it is whatever the `runas` caller passed. An elevated uninstaller that starts a helper by
bare name, uses `%ComSpec%`, or loads a DLL that is missing from its own directory resolves it through values a
medium process chose. Windows does the same for any elevated start, so this is hardening, not a new hole; B6
names the rule.

Fix: for a broker-route run pass an environment block built from the machine environment plus the profile
variables (no `HKCU\Environment` override of `SystemRoot`, `windir`, `ComSpec`, `PATH`, `PATHEXT`,
`ProgramFiles*`, `ProgramData`), and `current_dir` = the uninstaller's directory. Call
`SetCurrentDirectoryW(<install dir>)` at the top of the broker's `main`.

### S5. A reconcile that moved a foreign object back is not reported to the client

`live.rs:188-210` (`undo_result`) and 214-243 (`recovered_outcome`) return an outcome and conflict rows;
`history` (335-340) ignores every reconcile result but `Retried` and `Completed`. A `MismatchMovedBack` or
`MismatchKept` alert reaches no result and no History row. See flagged point 1.

### S6. The look-alike and invisible-character lists have gaps

`consent/text.rs:74-123`. Performed the "mislead with names" attack against the lists:

- Not escaped inside a word with ASCII letters: U+217C `ⅼ` and the other small Roman numerals (U+2170-217F),
  U+01C0 `ǀ`, Lisu letters (U+A4D0-A4FF, which are Latin capitals in shape), Cherokee small letters
  (U+AB70-ABBF), phonetic small capitals (U+1D00-1D7F). `Goog\u{217c}e` is shown as it is, with no flag.
- Not treated as invisible: U+2800 (Braille blank).
- A word wholly in one such script is shown by design; `\u{410}\u{440}\u{440}\u{4cf}\u{435}` reads "Apple".

Control characters, bidi controls, quotes, odd spaces, cuts and the "escaped name is an attention entry" rule all
work as the note says.

Fix: turn the rule around. In a word that holds an ASCII letter or digit, escape every alphabetic character that
is not in an allow-list (Basic Latin, Latin-1 letters, Latin Extended-A, Latin Extended Additional). Add U+2800.
For a path whose last component is wholly in a look-alike script while other components are ASCII, add the
attention reason without escaping.

### S7. The broker is started with `SW_HIDE`; its first window may inherit that

`BrokerLauncher.cs:340` (`nShow = SwHide`). Windows applies the start-up show command to a process's first
`ShowWindow` call in some cases. The first window of the broker is the consent dialog. If it comes up hidden, the
request waits for an answer nobody can give (fail-safe, but the flow is dead until the UI is closed). From
reading, not run. Fix under flagged point 4; it must be looked at on the first real elevated run.

### Notes

- **N1.** `uninstall.rs:256`: `remove_file` then `rename`. `std::fs::rename` replaces an existing file on
  Windows, so the removal only adds a window in which a crash loses the fingerprint. Drop it.
- **N2.** `BrokerLauncher.cs:267-270`: `TerminateProcess` on the handle `ShellExecuteExW` returned for an
  elevated process is refused for a medium caller. After a failed server check the broker stays until it has no
  client for ten minutes. Harmless; say so in the comment or close the pipe to count as a refused client.
- **N3.** `plan.rs:172-199`: one `bind` and one clone of the scan document per refused item. With the slow
  nested path that is cubic in the worst case. See flagged point 5.
- **N4.** The harvest and the signer check run elevated over user-writable files for medium-route programs
  (`uninstall.rs:551`, 566-578), and `scan.candidates` returns paths under a root the entry names. A medium
  client can thereby read names in directories its own token cannot list. Accepted by decision Q1 as I read it;
  worth one line in the threat table.
- **N5.** A page of 40 attention entries with long lines can be taller than the work area; `centered` keeps the
  top on screen, so the buttons are below it. Cancel by Esc still works. Lower `PAGE_ENTRIES` or cap by lines
  once the real dialog has been measured.
- **N6.** Fingerprints under `<data root>\fp` are never removed.
- **N7.** One unexecuted plan pins its scan (`plan.rs:279-285`): a UI that creates a plan and then lets the user
  go back must scan again. Let a second `plan.create` replace the first (remove the old id, claim again).
- **N8.** `execute.rs:228-229` sets `ran` only on `Ok`. If `execute_bound` can return `Err` after the session
  exists, the claim is released; `check_nothing_pending` then stops the next execute. State in `ExecBackend` that
  `Err` means "no session exists", or set `ran` when a session id is known.
- **N9.** `exec.md` and `broker-flow.md` still describe `uninstall.observed` without the window; update them
  with ba1394d.

## The attacks of the review point

| Attack | Result |
|---|---|
| Make the executor run something the dialog did not show | Holds for `plan.execute`, `undo.run`, `journal.*`: one `Arc<BoundPlan>` (`execute.rs:177-227`), `describes_plan` and the code compared before asking, previews bound to the journal mark. Gaps: M4 (content of a ticked parent), B1 and M1 (the uninstaller, which no dialog shows at all). |
| Run a plan of another scan | Holds. Typed ids, per-table lookup, `plan.create` accepts only top-level ids of its own scan (`plan.rs:131-152`). |
| Run a plan twice | The plan id holds (`Table::take`, `execute.rs:153`). A sibling scan gives a second run: S2. |
| Get a medium-route program run by the broker | The session check holds (`uninstall.rs:754`) and both sides compute the route themselves. The route itself is wrong for B1 and M2. |
| Mislead with names or paths | Escaping, quoting, cuts and the attention rule hold. List gaps: S6. |
| Lose or corrupt a session by killing the UI at each step | Holds by reading: before approval the `Closer` cancels the dialog (`serve.rs:758-764`, `lifetime.rs:178-211`); after approval the handler never reads `cancelled` and the supervisor waits for a mutating job (`serve.rs:765-771`); a killed broker leaves a write-ahead journal and `check_nothing_pending` blocks the next execute. One hang: S1. |
| Purge a user-data item without its own dialog | The split holds for items the executor classes as user data (`purge.rs:274-311`, `view_purge` refuses a user-data unit). The classing misses M4. |
| A standard user or another process reaches elevated behaviour | The pipe and start checks of R1 are intact. B1 and M2 are reachable by a medium process with a registry or file write and no pipe access. |

## Rulings on the flagged points

**1. UNDO: reconcile inside an approved run can move a foreign quarantine object back; no start hook.**
Accept, with one change. The move puts back, never over anything, an object Purge took by a boot-time move that
hit the wrong file; it reverses a change nobody approved, so it needs no dialog of its own. M3 schedules no
boot-time move (B10), so it can only happen for a session made by the rig CLI. No start hook: agreed, a start
is not a user action. Change (S5): "`UndoResult` and `OutcomeResult` carry `alerts[]` (`op`, `original_path`,
`moved_back`), filled from the run's reconcile results, and `history.get` marks the op; the History page shows
'Purge found another file in quarantine and put it back at <path>'."

**2. UNDO: a recovery with nothing to change runs without a dialog.**
Accept. The empty op list comes from the same preview the run is bound to (`*_expecting` with the journal mark),
and what runs writes Purge's own records only. Change the wording of B4 in the design and the note: "every
request that changes something outside Purge's store ends in a dialog". Add one test if it is not there: an
`Unindexed` session whose journal changes between preview and run is `NotAsShown`.

**3. PURGE: expiry ids are a hash; one declined user-data dialog gives `partial`.**
Ids: accept. They select a unit of a fresh listing, a collision refuses the listing, and the dialog is the gate.
Outcome: change. "When no dialog was approved, `quarantine.purge` answers `consent_declined` and the broker does
not end. `partial` with `kept` is the answer only when at least one unit was approved and at least one was not
purged." This is S3; `named.is_empty()` at `purge.rs:314` returns `Err(consent_declined())`.

**4. BROKER-CORE: `other_account` is not sent; a console window may flash.**
`other_account`: accept. Nothing answered before the peer check is the stronger rule, and the UI refuses a
standard user before any prompt. Console: change. "`purge-broker.exe` is built for the Windows subsystem
(`#![windows_subsystem = "windows"]`); failures go to the event log as now. The launcher passes `SW_SHOWNORMAL`."
That removes the console, the hidden conhost, and the risk of S7. Verify on the first elevated run that the
dialog is visible and in front.

**5. BROKER-FLOW: the bind fast path; crafted nested selections take the slow path.**
Accept. `any_nesting` is exact for canonical paths: sorted with the separator lowest, the neighbour after a
parent is the parent again or one of its descendants, and the document is the broker's own, so a client cannot
craft it; it can only pick ids. Note that a normal scan with absorbed children already takes the slow path for
`check_protected_descendants` (`nested` is computed over items and absorbed, `plan_in.rs` `bind_items`); only
`check_order` is usually skipped. The cost is bounded by `PIPE_IN_LIMIT` and the scan size, `plan.create` runs
beside at most seven other reads, and the only client is the checked UI. No change required; N3 is the cheap
improvement (collect all `NotSelectable` items in one `bind` pass).

**6. EXEC: `allow_irreversible` as an opt-in flag; the scan stays claimed.**
Accept both. The flag only widens what the dialog may ask, it is frozen in the plan, each package is an attention
entry and the box gates the button. Add to the note that the UI must not set the flag by default. The claim:
accept, and extend it to sibling scans (S2).

**7. EXEC: the medium route records the uninstall window at `uninstall.observed`.**
Design intent: accept, as built in ba1394d. Both ends are the broker's clock (`window_start` taken in `prepare`
before the harvest, the end at the observation), no time comes from the client, and a window is recorded only
when the report is not a failure and the broker's own verify-gone passed. Three changes:

- "`uninstall.observed` is refused with `wrong_route` for a broker-route session, and never raises a session
  that already ran" (M3).
- "The window is recorded by the first passing observation only." Today a repeated call moves `t_end` later
  (`uninstall.rs:841-844`), and the evidence "modified after the uninstall" is judged against `t_end`.
- "An observation more than 2 hours after `prepare` records no window" (the scan is then forced), so a client
  cannot stretch the window without bound.

## Verified to hold

By reading the code named; not by a run unless said.

- `plan.execute` draws `view::view` from the `Arc<BoundPlan>` in the table, checks `describes_plan` and that the
  view's code equals the code `plan.create` returned, and hands the same `Arc` to the executor.
  `execute_bound` binds nothing (`Run::start_bound`).
- `plan.create` takes ids only, sorts and dedups them, refuses an id that is not a top-level item of that scan,
  computes the confirm hash itself, and refuses unvouched system objects with the scan's own fingerprint.
- A plan id works once; a second `plan.execute` during an open dialog is `busy` before the handler, so the plan
  is kept.
- A declined, undrawable or lost dialog releases the scan and changes nothing; `Ctx::consent` asks nothing once
  the `Closer` fired.
- `uninstall.run` refuses a session whose route is not `Broker`; the medium engine refuses a route that is not
  `Medium` and checks the level against the shell (`stdio/uninstall.rs:253-257`). Neither takes the route from
  the other side.
- A per-user entry (an `HKU` hive or a user-writable key) is always `Medium`; a relative or unreadable executable
  is `Medium`.
- Scan mode: `post` needs ran, reported success and the broker's verify-gone; `forced: true` lowers; a stored
  fingerprint is `external`. Exception: M3.
- Undo and recovery: the dialog lists the preview's ops, the run refuses with `NotAsShown` when the journal mark
  or the covered ops differ, `check_intents` ties the journal's intent to the plan's op.
- Purge: every id is looked up in a fresh listing; an unknown id refuses the request before any dialog; the bulk
  view refuses a user-data unit; each user-data unit has `view_purge_user_data` and its own `confirm_user_data`;
  the executor refuses ids the consent does not name.
- Tables are bounded at 256, ids come from `BCryptGenRandom`, zero and taken ids are redrawn.
- The hive rule runs before the handler for `uninstall.prepare`, `leftovers.stored` and the stored scan.
- The fingerprint file name is a SHA-256 of the program id; a stored document that names another program is not
  used.
- Loss handling: parent or pipe loss fires the `Closer`, cancels cancellable jobs, waits for a mutating job
  without limit and for a read 10 s.
- `any_nesting` (see point 5).
- Text: control, bidi, zero-width, separators, non-plain spaces, private use and `"` are escaped; leading,
  trailing and doubled spaces are escaped; a name is always quoted; an escaped or cut name is an attention entry;
  attention entries are never folded.
- The dialog gate: the primary button is on the last page only, disabled until the box is ticked and the arming
  delay has passed; the box state is cleared on every page change.
- UI server check: pid from the held process handle, image path, elevation, before the first byte.

## Not verified

- Anything on the real elevated broker: UAC, the real pipe, the TaskDialog (never rendered from the broker),
  `LiveExec`, `LiveBackend`, `LiveMachine`. All of it is on the writers' VM lists and still open.
- The M2 act-time gates and `drive`'s error paths; `live_host.rs`; `stdio.rs`; both `icons.rs` files.
- Whether the tests named in the notes assert what their names say.
- M4 on a fixture; S7 on a machine.

## What was run

- `cargo test -p purge-broker --lib` at ba1394d (result below).
- The pipe experiment for B2 (result above).

Test result: `test result: ok. 190 passed; 0 failed; 0 ignored` (20.74 s). The shell reported exit code 1 for
the whole command line; cargo's output was piped through PowerShell with stderr merged, and I did not run it
again without the pipe to see cargo's own exit code. The test summary line is what I rely on.

## Is it reasonable for the user to try a full uninstall of a harmless test app on their own laptop now?

**Not yet through the UI, and the reason is that it will not work, not that it is dangerous.** With B2 the UI
cannot send `engine.hello` to the real broker: the attempt shows the UAC prompt, waits 30 s and fails with "The
administrator part ended." Nothing is changed.

**After B2 is fixed: yes**, on these conditions.

1. It is the first run of the real broker, dialog and executor outside tests. Treat it as that: a restore point
   first (`restore_point: always`), nothing else important open.
2. Install with `install.ps1` into Program Files, so the start checks pass (`Purge.exe` beside the broker, `kb`).
3. Pick a test app with a plain uninstaller: a per-user app, or a machine-wide one whose `UninstallString` is a
   quoted path to its own `.exe` under Program Files with no `%NAME%` and no `cmd`, `rundll32` or script host
   (B1, M2). 7-Zip or Notepad++ fit.
4. Check `reg query HKCU\Environment` first: no value named like a system variable (B1).
5. In the leftovers page keep the preselection. Do not tick a folder whose line says it holds items not known to
   belong to the app, and tick no user-data item (M4).
6. Read the broker's dialog and compare its code with the UI's. If no dialog appears within about ten seconds of
   "waiting for your answer", close the UI: the broker cancels the dialog and runs nothing (S7).
7. Do not use the purge of expired quarantine items (S3, M4). Nothing expires for 30 days anyway.
8. Keep a `rig-exec` build of the engine at hand: its `undo` restores the session if the UI's History & undo
   page fails. Quarantine is a move, and undo fidelity passed the M2 gate through that path.

B1, M1, M2 and M3 do not make that trial unsafe on a laptop the user controls; they must be closed before the
`m3-broker` gate.

## Fixes

Status of every finding and flagged point on `baseline` after the R2 fix rounds (merges efa8d39 r2-b2, 257cf6f
r2-m4, 8c7142f r2-b1, ea743b7 r2-s, a7813b4 r2-m1, and d4ee4c3 inno-installer, which carries r2-s7 641dcf7) and
the cleanup commits that add this section. Each test name below was checked against the tree (it exists where
named). Checks of the merged tree: `docs/HANDOFF-baseline.md` (unelevated `xtask ci` all pass on fe444fd). The
DECISIONS rows for the rulings are dated 2026-11-22 and marked "(coordinator)".

| Finding | Status | What changed |
|---|---|---|
| B1 | **Fixed** 65347f2 (merge 8c7142f) | `SystemSource::machine_env` (the Windows-derived values plus `HKLM\...\Session Manager\Environment`). `uninstall.prepare` expands a machine-scope command with it only; a per-user program keeps the user's map. `pipeline::route` expands with both maps: any difference, or a `%NAME%` neither defines (`has_undefined_reference`), is `Medium`. `run_uninstall` never expands a command given in `req.command` (the frozen one). Tests: `pipeline` and `flow_tests` `a_planted_user_environment_keeps_a_machine_command_medium`, `runner` `a_given_command_is_run_exactly_as_frozen`. |
| B2 | **Fixed** 8543cdb (merge efa8d39) | `BrokerPipe.TryOpen` opens with `FILE_FLAG_OVERLAPPED` (SQOS identification kept), runs the server check on the raw handle before any write, and wraps it in `NamedPipeClientStream(isAsync, isConnected)`. The test-only `pipe_harness` example serves the real broker pipe unelevated. Tests: `BrokerPipeTests` `HelloCompletesWhileTheServerStaysInAPendingRead`, `HelloCompletesAgainstTheRealBrokerPipeServer`, `AFailedServerCheckOnTheRealPipeOpensNoStream`. The user's desktop-PC trial (2026-11-22, fe444fd setup) talked to the real elevated broker. |
| M1 | **Fixed** 743ca9a (merge a7813b4), fix option 1 | `uninstall.run` is `consent: true` in `table.rs` and asks `view_uninstall`, drawn from the session's frozen command: program name, the exact command line (`text::shown_line`), signer, quiet or interactive, restore point (`RunParams.restore_point`, display only). Declined, undrawable or lost: `consent_declined`, nothing starts, the session stays usable. The UI shows a waiting state and a Retry bar. Tests: `consent::tests` `uninstall_shows_name_command_signer_mode_and_restore_point`, `uninstall_dialog_describes_only_the_command_it_was_drawn_from`, `uninstall_names_that_could_mislead_are_escaped_and_need_the_box`; `flow_tests` `run_asks_a_dialog_drawn_from_the_frozen_command_before_it_starts_anything`, `a_declined_dialog_starts_nothing_and_the_session_stays_usable`, `the_loss_of_the_pipe_while_the_dialog_is_open_starts_nothing`, `the_loss_of_the_parent_while_the_dialog_is_open_starts_nothing`; UI `A_declined_broker_dialog_runs_nothing_and_Retry_asks_again`. |
| M2 | **Fixed** 65347f2; residual reworked on branch `r2-m2-inline` per the Fable review of 6167e25 (H1, H2, M1, M2, L1); Fable re-review of 113b721: changes needed (M3, M4, L3; H3 in sid.rs) → fixed in 5a902e3; third Fable review of 3a135ed: changes needed (M5); H3, M3, M4, L3 closed → M5 + PATH filter fixed in d3178fd; fourth Fable review of f9bc039: changes needed (M6, L4); M5 + PATH filter closed → M6, L4, interpreter hosts fixed in 5268a09; fifth Fable review of 518b48b: changes needed (M7); M6, L4, interpreters, PATH closed → M7 fixed in 6e0d958; sixth Fable review of 9126b48: approved; optional follow-ups (`:` split, 8.3 names) in 2eb3360 | `route` judges a known host (`cmd`, `rundll32`, `wscript`, `cscript`, `mshta`, `regsvr32`, `msiexec`, `java`/`javaw`, `sdbinst`) on the file it is told to load (`host_load_path`); not found or not admin-only is `Medium`, and any absolute path in the arguments that exists and is user-writable is `Medium`. Tests: `pipeline` `a_user_writable_file_loaded_by_an_admin_only_host_is_medium`, `flow_tests` `a_user_writable_script_under_an_admin_only_interpreter_is_medium`. **Residual, reworked:** every `powershell`/`pwsh` line is `Medium`, `-File` and `-NoProfile` included (H1, H2: the user's profile and auto-loaded modules from `Documents\WindowsPowerShell\Modules` and HKCU `PSModulePath` are user-writable; injecting `-NoProfile` would break B1). `cmd` is `Medium` without `/d` before `/c`/`/k`/`/r` (M2: HKCU `AutoRun`), when the program it runs is itself a host (M1), or when its command text can run a second program. `rundll32` reads its DLL quote-aware from the raw line, and the user-writable argument check looks at each token whole and cut at a comma (L1: a comma could make `C:\ProgramData\Vendor,x\evil.msi` read as admin-only `C:\ProgramData\Vendor`). `msiexec` with a ProductCode is unchanged. Tests: `pipeline` `inline_powershell_command_text_is_medium`, `encoded_powershell_command_is_medium`, `positional_powershell_command_text_is_medium`, `powershell_with_an_admin_only_file_is_still_medium`, `cmd_without_d_before_c_is_medium`, `cmd_running_another_host_or_a_second_program_is_medium`, `a_comma_never_turns_a_user_writable_load_path_admin_only`. **Third round:** `cmd` is also `Medium` with `/s`, with command text whose quotes cmd could strip differently (one or more than two, two not enclosing the program at the start, `&<>()@^|` in the program; M3), or a program without an extension (M4); the argument check also judges the value of `NAME=value` and each `;`-part (L3); every file the route judges must pass `sid::is_admin_only_executable`, which also refuses a parent directory a non-admin may add a file or folder to (H3, DECISIONS H3 row). Tests: `pipeline` `cmd_quote_stripping_that_could_change_the_program_is_medium`, `a_user_writable_file_in_a_name_value_argument_is_medium`, `a_file_in_a_folder_users_may_add_to_is_medium`; purge-win `sid` `a_parent_users_may_add_to_is_not_admin_only_for_a_run`, `admin_only_executable_on_host`. **Fourth round:** a fully qualified argument path that does not exist is judged by its nearest existing folder, which must be admin-only; any other error is `Medium` (M5); an elevated run's machine `PATH` keeps only admin-only directories, in order (DECISIONS B1+S4 row). Tests: `pipeline` `a_missing_argument_file_is_judged_by_its_nearest_existing_folder`; purge-inventory `an_elevated_run_gets_the_machine_environment_and_the_uninstaller_directory`. **Fifth round:** a path not on a local fixed drive (UNC, `\\?\UNC\`, mapped, `subst`, removable) is never admin-only, for both `sid` rules (M6); a leading `//` counts as UNC in the argument check (L4); every interpreter or script host (`pipeline::INTERPRETERS`: python, node, java, wsl, wscript, mshta, ...) is `Medium`, also as the program under `cmd /c` (coordinator ruling). Tests: purge-win `sid` `drive_letter_spellings`, `remote_paths_are_never_admin_only`; purge-source `remote_and_non_fixed_volumes_are_never_admin_only`; `pipeline` `interpreters_and_script_hosts_are_medium`; purge-inventory `the_live_machine_path_keeps_the_expanded_system32`. **Sixth round:** any argument token whose file name is a host's or an interpreter's (`conhost --headless powershell ...`, `rundll32 shell32.dll,ShellExec_RunDLL powershell ...`) makes any command `Medium` (M7); `powershell_ise` and `dotnet` are interpreters. Test: `pipeline` `a_host_named_in_a_launchers_arguments_is_medium`. **Follow-ups (optional, after approval):** a part after a non-drive `:` is judged as a program name (`/RUN:powershell`); an 8.3 short file name (`POWERS~1.EXE`) in the program or an argument part is `Medium`; trailing dots and spaces are trimmed from file names. Test: `a_host_after_a_colon_or_behind_a_short_name_is_medium`. |
| M3 | **Fixed** 65347f2 | `observed` answers `wrong_route` unless the session is `Medium`; `record_observation` never raises a session that ran (`uninstaller_ok` only true to false); the first passing observation records the window, a later one leaves `t_end`; an observation more than 2 h after `prepare` records none (`OBSERVATION_WINDOW_CAP`). Tests: `flow_tests` `observed_cannot_raise_a_failed_broker_run`, `an_observation_records_the_window_once`; `uninstall` `an_observation_never_raises_a_session_that_ran`, `an_observation_window_is_capped_at_two_hours`. |
| M4 | **Fixed** 4bf2452 (merge 257cf6f) | `purge_plan::collapse::nested_candidates`: every candidate of the scan document that nests in a whole-tree item, absorbed or kept. The view lists the personal ones as "Taken with its parent" and gives the parent `Reason::UserData`; `expiry::Categories` marks such a parent user data, so its quarantine item gets its own purge dialog. Tests: `consent::tests` `user_data_below_a_ticked_parent_is_listed_and_makes_the_parent_user_data`, `expiry::tests` `a_parent_that_holds_a_user_data_item_is_user_data_and_purged_only_with_its_own_consent`. Not yet run on a rig fixture scan. Cost: `nested_candidates` is items x document per selected item (handoff note). |
| S1 | **Fixed** 5b0b22a (merge ea743b7) | `mark_broken` sets an `AtomicBool` and uses `try_send`; the supervisor reads the flag every tick. Test: `serve::tests` `a_full_event_channel_does_not_block_the_pipe_broken_signal` (the flag path; not reproduced end to end over a real pipe). |
| S2 | **Fixed** 5b0b22a | `Scan.program` + `spent`: a run spends every scan of the program; `plan.create` and `plan.execute` refuse a spent scan, and `plan.create` refuses a scan whose uninstall session is gone, both as `plan_refused` "scan again" (DECISIONS row). A fresh scan from the stored fingerprint after the run is allowed. Test: `exec_tests` `a_run_spends_every_scan_of_the_program` (a sibling plan made before the run, a new plan from the sibling, a fresh scan), and `a_scan_whose_session_vanished_cannot_be_planned_until_scanned_again` (r3-s2-test: the vanished-session refusal on its own - the session is taken out of the table without a run, since no method does that, so the scan is not spent; `plan_refused` "scan again", no dialog, nothing run; a scan of a session still there is planned as the control). |
| S3 | **Fixed** 4bf2452 | `quarantine.purge` with no approved dialog answers `consent_declined` and is not counted as a completed change. Test: `purge::tests` `declining_every_dialog_is_consent_declined_and_does_not_end_the_broker`. |
| S4 | **Fixed** 65347f2 | A broker-route uninstaller gets `uninstaller_environment` (the machine block plus the profile variables, nothing from `HKCU\Environment`) and its own directory as working directory (`spawn_in_job` with a `SpawnContext`); the broker's `main` calls `start::restrict_working_directory` (its install directory). Test: `runner` `an_elevated_run_gets_the_machine_environment_and_the_uninstaller_directory`. The real elevated start is VM work. |
| S5 | **Fixed** 5b0b22a, UI part partial | `UndoResult.alerts[]` and `OutcomeResult.alerts[]` (`Alert {op, original_path, moved_back}`) from the run's reconcile results; `HistoryItem.alert` marks the op in `history.get`. Shown on the Leftovers "Put back" result panel. The History page is still sample data, so it does not show the mark yet. Test: `undo_tests` `a_reconcile_alert_reaches_the_undo_and_recovery_results`. |
| S6 | **Fixed** 4bf2452 | In a word with an ASCII letter or digit, every alphanumeric character outside Basic Latin, Latin-1, Latin Extended-A and Latin Extended Additional is escaped; U+2800 is invisible; a path whose last component is wholly look-alike while earlier ones are ASCII is an attention entry without escaping. Tests: `consent::text` `the_added_look_alike_scripts_are_written_out_in_a_latin_word`, `a_braille_blank_is_invisible`, `a_path_whose_last_component_is_look_alike_is_flagged_without_escaping`. |
| S7 | **Fixed** 641dcf7 (in d4ee4c3) | `#![windows_subsystem = "windows"]` in the broker's `main.rs`; the launcher passes `SW_SHOWNORMAL`. dumpbin: subsystem 2 (Windows GUI), `0800 Dependent Load Flag` kept. The desktop-PC trial got through its dialog; foreground and secure-desktop behaviour stay on the VM list. |
| Point 1 | **Accepted, changed** | As S5. No start hook. |
| Point 2 | **Accepted, reworded** | B4 in `M3_DESIGN.json` and T2 in `M3_DESIGN.md` now say "outside Purge's store"; `docs/m3-notes/undo.md` choice 5 says so. Test added in this cleanup: `purge-exec` `an_unindexed_recovery_whose_journal_changed_after_the_preview_is_not_as_shown`. The broker side was already covered by `a_recovery_that_changes_nothing_on_the_machine_runs_without_a_dialog`. |
| Point 3 | **Accepted, changed** | As S3. Ids: no change. |
| Point 4 | **Accepted, changed** | `other_account` not sent: no change. Console: as S7. |
| Point 5 | **Accepted** | No change required. N3 below. |
| Point 6 | **Accepted** | The flag and the claim stay; the claim extends to sibling scans (S2). `docs/m3-notes/exec.md` now says the UI must not set `allow_irreversible` by default; the UI does not send it at all yet. |
| Point 7 | **Accepted, changed** | As M3. |

| Note | Status | What changed |
|---|---|---|
| N1 | **Fixed** (this cleanup) | `write_fingerprint` no longer removes the old file before `rename`; the comment says why (`MOVEFILE_REPLACE_EXISTING`). |
| N2 | **Fixed, comment** (this cleanup) | `BrokerLauncher.Terminate` says it is best effort: the elevated handle refuses a medium `TerminateProcess`, and the broker ends on parent loss or after ten idle minutes. No behaviour change. |
| N3 | **Deferred** | Collecting every `NotSelectable` in one `bind` pass needs a change to `purge-exec`'s `plan_in` API (the executor's bind). Ruling 5 needs no change; the cost is bounded by the pipe limit and the scan size. Noted in `docs/m3-notes/broker-flow.md`. |
| N4 | **Fixed, doc** (this cleanup) | Threat-table row T17 in `M3_DESIGN.md` (accepted with answer 1). |
| N5 | **Deferred** | Lowering `PAGE_ENTRIES` or capping by lines changes the consent dialog's paging; the real dialog must be measured on the VM first. |
| N6 | **Deferred** | Removing fingerprints under `<data root>\fp` needs a retention rule (a stored fingerprint is what `leftovers.stored` and a later scan use): a design choice, not a nit. |
| N7 | **Deferred** | Letting a second `plan.create` replace the first changes the scan-claim rules S2 just tightened, on the path to the consent dialog; it wants its own change and review. The UI scans again meanwhile. |
| N8 | **Fixed, doc** (this cleanup) | `ExecBackend::execute` now says `Err` means nothing on the machine changed, not that no executor session exists; the claim is given back for that reason, and a leftover session is for `check_nothing_pending` and recovery to judge. Setting `ran` on `SessionCreated` would change `plan.execute` behaviour and was not done. |
| N9 | **Fixed, doc** (this cleanup) | `docs/m3-notes/exec.md` ("`uninstall.observed` outcome") and `broker-flow.md` describe the window and the M3 rules, with their tests. |
