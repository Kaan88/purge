# M3 design: UI + broker

Status: **complete, 2026-11-21.** Package list: `docs/M3_DESIGN.json`. Decisions: section 16 and
`docs/DECISIONS.md`. Sections 7 (the user's answers) and 7a (mockup deltas) are binding and unchanged.

Milestone row (ENGINE_PLAN.md 11.1): WinUI shell (S1, S2, S3, S4, S7), custom Main, launch bench + S1 skeleton
bench, `--broker` (pipe, identity, consent TaskDialog), per-user runner in the medium engine, `programs.patch`, icon
batches. Exit: the launch gates of 1.3, end-to-end on the M1 apps via UI automation, broker consent cannot be driven
from medium IL (manual `SendInput` test), starts on clean Windows.

## 0. Summary

- Three programs: `Purge.exe` (UI, medium), `purge-engine.exe --stdio` (medium, read-only plus the per-user
  uninstaller), `purge-broker.exe` (elevated, a new binary, the only release binary that links the executor).
- Every uninstall asks for UAC once. The broker harvests, scans and plans by itself. The UI sends ids only.
- The broker shows the consent in its own TaskDialog and runs the plan object the dialog was drawn from.
- The broker is the pipe server. Each side checks the other: pid, creation time, image path, account.
- The broker takes no directory from the environment and runs only from an admin-only directory on the system volume.
- Nine mockup pages are built (7a). The UI starts from the stopgap tree at 0d9c008 (question 7).
- 33 packages in 8 waves, three Fable reviews, gate report `docs/M3_GATE.md`.

## 1. Where the code stands

- `crates/purge-rpc` holds only `EngineHello` and the baseline status types (`crates/purge-rpc/src/lib.rs:15-89`).
  No framing, no method table, no capability sets. M3 writes all of it.
- `bins/purge-engine`: `--stdio` and `--broker` parse and exit 1 (`cli/args.rs:450-451`, `cli.rs:386-394`).
  Executor verbs exit 5 unless built with `rig-exec` (`cli.rs:288-309`). `main.rs:30`, `:53` take the baseline
  directory from `PURGE_KB_DIR` and the data root from the `ProgramData` environment variable.
- `bins/purge-engine` is also a library (`src/lib.rs`: `cli`, `pipeline`). `pipeline.rs` holds `inventory` (`:292`),
  `harvest` (`:403`), `uninstall` (`:528`), `scan` (`:685`), `m1b_lists` (`:1148`). The broker calls these.
- `tools/xtask check-deps` rule 4 (`check_deps.rs:11-14`): only purge-engine links purge-exec, and only with
  `rig-exec`. M3 rewrites this rule (package M3-DEPS).
- `purge-exec` has what the broker calls: `plan_in::bind` (`plan_in.rs:432`), `execute::execute`
  (`execute.rs:2307`), `undo::undo` (`undo.rs:1180`), `recover::{pending, resume, rollback, retry_held}`
  (`recover.rs:310`, `:853`, `:859`, `:1317`), `expiry::{expiring, purge}` (`expiry.rs:522`, `:998`),
  `StorageRoots::installed` (`storage.rs:954`, already uses the known-folder API).
- The rig `exec` verb reads a plan file, a sidecar and a selection file (`cli/exec.rs:705-768`). Its fingerprint
  binding for service, task and firewall items is optional and incomplete (`cli/exec.rs:893-898`). The broker makes
  it mandatory.
- `ui/` holds a README only. Prior art: 0d9c008 (stopgap, wired to the CLI engine) and 5d7df3c (alpha, no deletes).
  Both read; see `docs/m3-notes/reading-b.md` and question 7.
- `install/install.ps1` installs `purge-engine.exe` and `kb\` only, and registers nothing
  (`docs/m3-notes/reading-a.md` section 5).

## 2. Inherited requirements

| Source | Requirement for M3 |
|---|---|
| ENGINE_PLAN 3.1, D3 | Consent is the broker's own high-IL TaskDialog; `plan.execute`, `undo.run`, `quarantine.purge` take ids only; the broker executes only plans it built from its own scans; irreversible verbs need a fresh prompt naming every item |
| DECISIONS 2026-11-15 (`--confirm`) | Confirm hash = SHA-256(plan hash, selection hash). The dialog must bind to it: what is shown is what `plan_in::bind` runs |
| DECISIONS 2026-11-15 (Restart Manager) | M2 queries only, never closes or restarts anything, never chooses a boot-time delete. "Reverse if: M3 consent": open question 5 |
| DECISIONS 2026-11-16 (expiry) | A purge needs a consent naming every item and file; user-data items are confirmed one by one; a session without its scan copy counts every item as user data |
| DECISIONS 2026-11-17 (R3b S3) | The fingerprint's hash goes into the scan sidecar; the broker owns the hand-over from harvest to scan to exec |
| DECISIONS 2026-11-21 (W4) | The local baseline builds when the broker starts and never blocks a scan; a waiting scan raises the build's I/O priority and is offered again when the build completes (`BaselineBuild` in `engine.hello`) |
| M2_GATE 8 | The UI reads exit/outcome codes 10 (partial), 11 (undo with conflicts) and 12 (session not closed) as different outcomes. Releases are built with `-p purge-engine` |
| M1B_GATE 5 (R8b M1) | A resumed service undo cannot assign the owner of a re-created subkey. Revisit with the broker's privilege handling (`SeRestorePrivilege`): open question 6 |
| HANDOFF-m1b | Test broker elevation with the UAC prompt on (the dev host runs `ConsentPromptBehaviorAdmin=0`). Engine features the UI alpha wanted: object display name and program in the scan output, typed warning kinds, firewall names in `plan show` |
| BL-R1 S4 | An elevated engine ignores `PURGE_KB_DIR` unless built with the rig feature, takes the data root from the known-folder API, and trust decisions (`shipped_dir_trusted`, `LocalCache::open`, `table_cache`) require a fixed local volume |
| BL-R1 N5 | A fingerprint or plan made at medium integrity is a document its author can edit. The broker harvests and scans itself, or treats such a document's evidence like a `UserWritable` source |
| BL-R1 N6 | The unelevated engine gets no local baseline cache. Scans whose result is shown to the user run in the broker |

## 3. Architecture

### 3.1 Processes

| Process | Level | Lifetime | Role | Links the executor |
|---|---|---|---|---|
| `Purge.exe` | medium, `asInvoker` | while the window is open | UI only | no (C#) |
| `purge-engine.exe --stdio` | medium | started by the custom Main, dies with its job | inventory, icons, sizes, `inventory.changes`, session index, medium-route uninstallers | no |
| `purge-broker.exe` | high, one UAC prompt | from the Uninstall, Restore or History-detail click until 3.6 | harvest, broker-route uninstallers, scan, plan, consent, execute, undo, recovery, expiry purge, local-baseline build | yes |
| `purge-engine.exe <verb>` | either | one shot | rig and power use; executor verbs still exit 5 without `rig-exec` | only with `rig-exec` |

`purge-broker` is a new package `bins/purge-broker` with a library and a thin `main.rs`. It depends on the
`purge-engine` library (for `pipeline`), `purge-exec`, `purge-rpc` and `purge-win` with `write`. It has no cargo
feature at all: no `rig-exec`, no `fault-inject`, no `test-support`. A release is two builds:
`cargo build --release -p purge-engine` and `cargo build --release -p purge-broker`. Never `--workspace`.

### 3.2 What runs where

| Step | Process | Note |
|---|---|---|
| Program list, icons, sizes | medium engine | display only; nothing from it is evidence |
| Harvest, verify-gone, scan, plan | broker | also for per-user apps (answer 1, N5, N6) |
| Uninstaller of a machine-scope entry whose path has admin-only ancestors | broker | ENGINE_PLAN 4.4 |
| Uninstaller of a per-user entry, or of a path a user can write | medium engine | Purge is never an elevation vehicle |
| Consent, execute, undo, resume, rollback, purge | broker | one TaskDialog per mutating request |
| Session list and quarantine usage | medium engine | reads `sessions\index.json` (Users: read) |
| Session detail (per-item state) | broker | session files have no Users ACE |

Route rule. The broker computes `route` (`broker` or `medium`) in `uninstall.prepare` from its own inventory. The
medium engine computes the same rule from its own inventory. Each side refuses a program of the other route. The
command and signer the UI shows come from the process that will run the command.

Order for a medium-route app: `uninstall.prepare` (broker, harvest), then `uninstall.run_user` (medium engine),
then `uninstall.observed` (broker). The broker believes nothing the UI reports about the run. It runs verify-gone
itself. A skipped or failed uninstaller ends in `forced` mode with nothing preselected.

Queue. A queue of several apps runs in one broker, one app after the other (prepare, run, scan). Reviews follow
in order. Each app has its own plan and its own consent. Items shared with an app still installed stay protected by
the ownership index.

### 3.3 Pipe and handshake

The broker is the pipe **server**. ENGINE_PLAN line 151 says the UI creates the pipe, but line 152 has the broker
check "the client". The server side sets the DACL at high integrity and can identify its client, so the broker
serves.

1. The UI makes a 128-bit random name and starts `purge-broker.exe --pipe <name> --parent <pid> --parent-ctime
   <filetime>` with `ShellExecuteExW("runas")` on an STA thread (`SEE_MASK_NOCLOSEPROCESS`, no owner window (hwnd 0), see DECISIONS 2026-11-23 "UAC prompt owner").
2. The broker runs its start checks (3.4). Then it creates `\\.\pipe\purge-<name>` with
   `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, one instance, DACL = the broker's user SID and
   SYSTEM. If the name exists already, it exits.
3. The UI connects with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (retry for up to 10 s). It checks that
   `GetNamedPipeServerProcessId` equals the pid of the process handle that `ShellExecuteExW` returned.
4. The broker checks the client: `GetNamedPipeClientProcessId` equals `--parent`; the process creation time equals
   `--parent-ctime`; the image path equals `<broker's own directory>\Purge.exe`; the client's user SID
   (`ImpersonateNamedPipeClient`, `OpenThreadToken`, `RevertToSelf`) equals the broker's own user SID.
5. A client that fails step 4 is disconnected. After three failed clients the broker exits.
6. The first request is `engine.hello`. Nothing else is answered before it.

The broker keeps a handle to the parent process from step 4 on. The pid cannot be reused while it is held.

### 3.4 Broker start checks (before the pipe exists)

| Check | Failure |
|---|---|
| `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` is the first call in `main` | (no failure path) |
| The process token is elevated | exit, code `not_elevated` |
| Own directory: on the system volume, no reparse point on the path, every ancestor writable by administrators only | exit, code `install_untrusted` |
| Data root = known folder ProgramData + `\Purge` (never the environment); `StorageRoots::installed().check()` passes | exit, code `store_integrity` |
| KB and baselines = `<own directory>\kb`. `PURGE_KB_DIR` is not read. | (none) |
| Standard handles are closed; `ShellExecuteExW` inherits no others | (none) |

The exit code and one line go to the Application event log, because no pipe exists yet. When the process exits
before the pipe appears, the UI shows "The administrator part could not start" with the code.

"System volume" means the volume of the Windows directory. This closes BL-R1 S4: a volume written on another
machine cannot be the running system volume. The defaults of `install.ps1` are on it already.

The same rule goes into `purge-engine` for an elevated CLI run: known-folder data root, and `PURGE_KB_DIR` honoured
only in a `rig-exec` build or when not elevated (package M3-HARDEN).

### 3.5 Accounts

- The broker refuses a client of another account (step 4): error `other_account`. This is the standard-user case,
  where UAC asks for another account's credentials (answer 3).
- The UI checks first. When its token is neither elevated nor the limited half of an administrator token
  (`TokenElevationType`), a click that needs the broker shows "Administrator permission is not available. This needs
  an administrator account; this account is a standard user." and starts nothing.
- The UI found elevated (started "as administrator", or UAC off): the "Administrator" chip shows. The broker
  starts through the same `runas` call, which then shows no prompt.
- The medium engine runs a medium-route uninstaller only when its own token has the same user and the same
  elevation as the shell's token (owner of `GetShellWindow`). Otherwise it refuses with "start Purge normally".
  With UAC off both are elevated, so it runs.
- The setting "Always start as administrator" is not built in M3 (section 15).
- All per-user paths come from the checked account: `HKU\<SID>` and the known folders of that token.

### 3.6 Sessions and lifetime

- The broker holds in memory: `session_id` (one harvest and uninstall of one program), `scan_id`, `plan_id`.
  The fingerprint is also stored under `%ProgramData%\Purge\fp` (administrators only), as today.
- `plan.create` builds an `ExecRequest` from the broker's own `ScanDoc` and the selected ids, computes the confirm
  hash itself and calls `plan_in::bind`. The request is frozen behind an `Arc`.
- `plan.execute` draws the dialog from that `BoundPlan` and then runs the same frozen request. Package M3-EXEC adds
  `execute_bound`, so the executor takes the `BoundPlan` that was shown and derives nothing a second time.
- The session's fingerprint is always passed to the object binding (`unbound_objects`). There is no optional `--fp`.
- One mutating request at a time. A second one gets `busy`. Across brokers the store has one writer at a time
  (`sessions\writer.lock`, purge-exec; DECISIONS 2026-11-22 R3): another broker's run, undo, recovery or purge
  is `busy` too.

| Event | The broker |
|---|---|
| Execute, undo, recovery or purge completed, no other session open | sends the result, waits up to 5 s for the client to close, exits |
| No request for 10 minutes | exits |
| Parent handle signalled or pipe broken, nothing running | exits |
| Parent gone or pipe broken while an uninstaller, execute, undo or purge runs | finishes it, closes the session, writes the report and index, exits |
| Parent gone or pipe broken while the consent dialog is open | closes the dialog as Cancel, exits |
| Local-baseline build running at exit | stops the build between phases; a partial cache is never written |

After an idle exit the review is not lost. The UI starts a new broker (UAC again) and calls `leftovers.scan` with
the stored program. The broker scans again from its stored fingerprint. The UI applies the old ticks by candidate
id (`CandidateId` is a stable hash of the target, `crates/purge-model/src/ids.rs:259`) and lists what changed.

Local baseline (DECISIONS 2026-11-21, W4): the broker checks and builds it on a background thread at start.
`engine.hello` carries `baseline_build`; `baseline.changed` reports progress. A scan never waits. A scan that
finished while the build ran is offered again when the build completes.

## 4. Threat model for the broker

Trust statement kept from the plan: a same-user process with a shell is the user. The broker is defence in depth
against automation and against a standard user. It is not a sandbox for the administrator's own account.

| # | Threat | Answer | Test |
|---|---|---|---|
| T1 | A medium process of the same user drives the consent | The dialog belongs to the high-integrity broker; UIPI blocks input and messages from below. Cancel is the default button. No owner window from another process. | VM `m3-consent`: `SendInput`, `PostMessage`, UI Automation Invoke from medium fail; the same from high succeeds (control) |
| T2 | A medium process starts its own broker and talks to it | Client check of 3.3 step 4: pid, creation time, image `<own dir>\Purge.exe`, same account. An accepted client still sends ids only, and every change outside Purge's store still ends in the dialog (B4; a recovery that only writes Purge's own records runs without one, review M3-R2 point 2). | VM `m3-broker`: wrong pid, wrong creation time, a copy of `Purge.exe` elsewhere, a second client |
| T3 | The client supplies evidence (BL-R1 N5) | No request type has a field for a path, target, fingerprint, scan or plan. Requests hold ids, enums, booleans and integers. Unknown fields are refused. | ci: a schema walk over every broker request type; a fuzz of extra fields |
| T4 | Plan tampering between consent and execution | The plan lives only in broker memory. The dialog and the executor use one frozen `BoundPlan`. The act-time gates re-check every item. | ci: `plan.execute` on a plan id of another scan, a reused plan id, a changed selection |
| T5 | Pipe squatting or a fake broker | Random name, first instance only, the broker exits when the name exists. The UI checks the server pid against its own process handle. | VM `m3-broker`: pipe created first by a medium process; a medium process serving the name |
| T6 | DLL planting, or a replaced binary | Start checks of 3.4: admin-only directory on the system volume, System32-only DLL search, static CRT. | VM: a user-writable copy of the install directory; a DLL next to the broker in that copy |
| T7 | Directories from the environment (BL-R1 S4) | The broker reads no directory from the environment. | VM: `ProgramData` and `PURGE_KB_DIR` set to a planted tree before the `runas` call |
| T8 | A standard user gets an elevated delete | The broker refuses another account's client; the UI says an administrator account is needed. | VM `m3-uac`: standard user, administrator credentials typed at the prompt |
| T9 | Purge runs a user-writable command elevated | Route rule of 3.2; the broker refuses a medium-route program; the medium engine refuses when it is elevated above the shell. | ci: route table; VM: per-user VS Code runs at medium (process integrity recorded) |
| T10 | The broker's token is used for more than undo needs | `SeRestorePrivilege` is enabled on an impersonation token of one thread, around the reopen and owner-set of a key this undo created, and dropped on scope exit. No other privilege is ever enabled. | win-unit elevated: privilege state before, inside, after; a source check for one call site |
| T11 | The UAC prompt is misread or copied | The prompt names `purge-broker.exe`, publisher unknown until signing (answer 4). Any program can show a UAC prompt; the consent dialog, not UAC, is the approval. | documented in the first-elevation text |
| T12 | Text in the dialog misleads (vendor names, odd paths) | Names and paths are escaped: control and bidirectional characters are shown as `\u{...}`, names are cut at 80 characters, no hyperlinks. | ci: view-model tests with RLO, newlines, long names |
| T13 | The client floods or stalls the pipe | Request line limit 4 MiB, then the broker closes the pipe. Writes time out after 30 s. A running change still completes (3.6). | ci: oversize line, slow reader |
| T14 | The check of the image path races | The broker holds the process handle from the check on. A same-user process can still inject into `Purge.exe`: that is the trust statement, and T1, T3, T4 still hold. | none (accepted) |
| T15 | Thousands of items hide one bad item | Section 8: items that need attention are never cut and never summarised. | ci: 5,000-item plan view |
| T16 | An elevated UI (no boundary between UI and broker) | Medium processes still cannot reach either. The dialog is still shown. The setting that makes this the default is not built in M3. | VM: UI started elevated, flow completes, chip shown |
| T17 | The checked client reads names it cannot list itself | `uninstall.prepare` harvests, and checks the signer, elevated, also for a medium-route program whose files the user can write; `scan.candidates` returns paths under a root the entry names. A medium client can so learn names in a directory its own token cannot list. Nothing is changed and nothing is read but names and signer facts. Accepted with answer 1 (the broker harvests for every program, per-user ones included; review M3-R2 N4). | none (accepted) |

Not covered, by the trust statement: code inside the administrator's own medium session that waits for the user to
click "Move" on a plan the user really made, or that shows the user a false review list before a true dialog.

## 5. Scope

### 5.1 In

| Area | In M3 |
|---|---|
| Protocol | NDJSON JSON-RPC 2.0 in `purge-rpc`: framing, limits, method table, capability sets, error kinds, DTO schemas |
| Medium engine | `--stdio` server: `engine.hello`, `programs.*`, icons, sizes, `inventory.changes`, `history.index`, `uninstall.route`, `uninstall.run_user` |
| Broker | `purge-broker.exe`: section 3, the methods of 6.3, the consent dialog in four variants (section 8) |
| Hardening | BL-R1 S4, N5, N6; R8b M1 owner restore; the check-deps rule; standard-user refusal |
| UI | The nine pages of 7a: Programs, Uninstall pipeline, Leftovers, the "confirm in the security prompt" state, History & undo, Quarantine vault, Settings, narrow layout, high contrast |
| Scan modes | `post` after an uninstall; `forced` only after a failed or unverified uninstall of a listed program; a stored-fingerprint scan for a program removed outside Purge (7a delta 5) |
| Recovery | Pending-session banner, Resume and Roll back, retry of held items, each through consent |
| Expiry | Purge of items past retention, through the purge dialog (first to be cut, section 15) |
| Tooling | `xtask gen-dto`, `xtask bench-launch`, the `ui` step of `xtask ci`, rig modes `m3-*`, `install.ps1` update |

### 5.2 Out

| Item | Where it goes |
|---|---|
| Closing apps, stopping services, restarting Explorer, boot-time moves or deletes | later, needs its own consent design (answer 5) |
| Standard-user accounts | M4 (answer 3) |
| Consent variants B and C; any delete without quarantine at clean time | not planned (7a delta 3) |
| "Always start as administrator" | M4 |
| "Empty quarantine" (purge before retention ends) | M4 |
| "Force remove" of a folder or a portable app (`scan --path`), "Remove entry", "Modify" | M4 with the forced and external modes; the buttons are hidden, not disabled |
| The pre-harvest cache for external uninstalls | M4 (the M3 banner works only with a fingerprint the broker stored) |
| Knowledge-pack and "Always keep" settings, other profiles, compact rows | M4 (S5) |
| Assistant, command palette, tabs, triage, drop target, diff, tidiness, footprint map | 7a |
| Signature check of the caller | when a certificate exists (answer 4) |
| Store tab in Programs | M4 |
| WinAppSDK major upgrade and re-bench | scheduled task, before 2027-04-29, after the M3 gate |

## 6. RPC

### 6.1 Framing (`purge-rpc`)

- One JSON-RPC 2.0 object per line, UTF-8, `\n` ends a line. No batch arrays.
- Request ids are unsigned integers chosen by the client. A notification has no id.
- Progress notifications carry `request`: the id of the request they belong to.
- Cancel: notification `$/cancel {request}`. A running uninstaller, execute, undo or purge is not cancellable;
  harvest, scan and list are. The consent dialog is cancelled only by its own Cancel button or by 3.6.
- Limits: 4 MiB per line into the broker, 64 KiB into the stdio engine, 16 MiB out. Over the limit the server
  closes the transport.
- Every request type has `deny_unknown_fields`. Unknown methods and methods outside the transport's sets both
  answer `-32601`.
- `purge-rpc` stays free of `purge-win` and of I/O handles: it has the types, the codec over `Read`/`Write`, the
  table and a dispatcher trait. `purge-mcp` may still depend on it.

### 6.2 Capability sets

| Set | Meaning | stdio engine | broker pipe |
|---|---|---|---|
| Read | no side effect | yes | yes |
| UserRun | starts the user's own uninstaller at the user's level | yes | no |
| Propose | builds a plan in memory, no side effect on the machine | no | yes |
| Execute | harvest store writes, broker-route uninstallers, and everything behind a consent dialog | no | yes |

A server is built with a set mask. The method table names one set per method. One test walks the table for each
transport.

### 6.3 Methods (⇢ = notification)

Medium engine over `--stdio`:

| Method | Set | Params and result |
|---|---|---|
| `engine.hello` | Read | result `EngineHello` (as today) plus `elevation_type`, `shell_matches` |
| `programs.list` ⇢ `programs.batch`, `programs.patch` | Read | result `{count}`; raw ARP rows first, MSI, Burn and AppX details as patches |
| `programs.get` | Read | `{program_id}`, result: details-pane data |
| `programs.icons` ⇢ `icon.batch` | Read | `{program_ids[], px}`; each icon is base64 BGRA, at most 32 per line |
| `programs.sizes` ⇢ `size.ready` | Read | `{program_ids[]}` |
| `inventory.changes` | Read | result `{disappeared[], appeared[]}` against the last list stored in `%LOCALAPPDATA%\Purge` (display only) |
| `history.index` | Read | result: session summaries from `sessions\index.json`, and usage and cap per volume |
| `uninstall.route` | Read | `{program_id}`, result `{route, command, quiet_command, signer, running[]}` |
| `uninstall.run_user` ⇢ `uninstall.progress` | UserRun | `{program_id, quiet}`, result `{exit_code, outcome}`; refused for a broker-route program and by the level rule of 3.5 |

Broker over the pipe:

| Method | Set | Params and result |
|---|---|---|
| `engine.hello` | Read | result `EngineHello` with `elevated: true` and the baseline status |
| ⇢ `baseline.changed` | Read | `BaselineBuild`, and `rescan_offered[]` (scan ids) when a build completes |
| `uninstall.prepare` ⇢ `prepare.progress` | Execute | `{program_ids[]}`, result per program `{session_id, route, command, quiet_command, signer, co_products[], running[], fingerprint_summary, warnings[]}` |
| `uninstall.run` ⇢ `uninstall.progress` | Execute | `{session_id, quiet, restore_point?}`, result `{exit_code, outcome, verify_gone}`; broker route only. Ends in the broker's consent dialog (program, exact frozen command, signer, quiet or interactive, restore point); a declined dialog is `consent_declined` and starts nothing (R2 M1) |
| `uninstall.observed` | Execute | `{session_id}`, result `{verify_gone}`; after a medium-route run |
| `leftovers.stored` | Read | `{program_ids[]}`, result: which have a stored fingerprint |
| `leftovers.scan` ⇢ `scan.progress` | Read | `{session_id, forced?}` or `{program_id}` (stored fingerprint), result `{scan_id, mode, counts, baseline_trust, warnings[]}`. The client can ask for `forced`; it can never raise a mode. |
| `scan.candidates` | Read | `{scan_id, offset, limit}` (limit at most 500), result: items with band, kind, display name, owner program, size, typed warnings, preselected flag |
| `candidate.explain` | Read | `{scan_id, candidate_id}`, result: evidence lines, blockers |
| `plan.create` | Propose | `{scan_id, selected[]}` or `{scan_id, preselected: true}`, result `{plan_id, plan_hash, code, counts, bytes, attention[], warnings[]}` or a refusal list |
| `plan.execute` ⇢ `consent.shown`, `exec.progress` | Execute | `{plan_id, restore_point, delete_after?}` (`off`, `high_risk`, `always`), result `{outcome, session, counts, held[], restore_point, delete_after?}`. With `delete_after: true` ("delete instead of keeping in quarantine", DECISIONS 2026-11-24) the broker, once the run is recorded, sends `exec.progress` with phase `delete_after` and asks in a second dialog (the "Delete now" variant, a second `consent.shown` with its own code) whether the quarantined items of this run's session are deleted for good; the result's `delete_after {outcome, purged, kept}` says what became of that (`deleted`, `partial`, `declined`, `nothing`, `failed`), and `outcome`, `counts` and `held` stay the move's. The flag names no item |
| `history.get` | Read | `{session}`, result: items with state |
| `undo.run` ⇢ `consent.shown`, `undo.progress` | Execute | `{session, item_ids?}`, result `{outcome, conflicts[]}` |
| `journal.pending` | Read | result: interrupted sessions |
| `journal.resume`, `journal.rollback`, `journal.retry_held` ⇢ `consent.shown` | Execute | `{session}`, result `{outcome}` |
| `quarantine.expiring` | Read | `{include_not_due?, include_backups_not_due?}`, result: items past retention, with files and the user-data flag; with `include_not_due` also the quarantined items before it, each marked `due: false` (for "Delete now", DECISIONS 2026-11-23); with `include_backups_not_due` also the backups before theirs, per op, `class: Backup`, `due: false` (DECISIONS 2026-11-24) |
| `quarantine.purge` ⇢ `consent.shown` | Execute | `{expiry_ids[]}`, result `{outcome, purged, kept, purged_backups}`. An id of an item that is not due is asked for in the "Delete now" dialog, an id of a backup that is not due last, in the dialog that deletes backups early (the broker reads "not due" and the kind from its own listing; the request cannot say either) |
| `broker.shutdown` | Read | the broker exits when nothing runs |

`code` is the first eight hex digits of the confirm hash, written `A1B2-C3D4`. The UI shows it while it waits; the
dialog shows it in its footer.

Not in M3, though in ENGINE_PLAN 3.3: `location.inspect`, `references.find`, `guard.explain`, `plan.validate`,
the agent group, `kb.*`.

### 6.4 Outcomes and errors

Results carry `outcome`. These are not errors:

| `outcome` | CLI exit it mirrors (`cli.rs:68-131`) | The UI shows |
|---|---|---|
| `complete` | 0 | the result page |
| `partial` | 10 | the result page with the held and failed items, and what holds them |
| `undo_conflicts` | 11 | restored items and the conflict list |
| `not_closed` | 12 | "The session was not recorded completely"; History offers recovery. It wins over the two above. |

Errors (`error.data.kind`):

| Kind | Mirrors | Meaning |
|---|---|---|
| `consent_declined` | none | Cancel in the dialog; nothing was done |
| `plan_refused` | 6 | `bind` refused; `data.refusals[]` names items and reasons |
| `needs_recovery` | 8 | an interrupted session comes first |
| `store_integrity` | 9 | the store or a journal failed its check |
| `uninstall_failed` | 4 | exit code, and the offer of the forced mode |
| `other_account`, `not_elevated`, `install_untrusted` | 7 | 3.4, 3.5 |
| `wrong_route` | none | a program of the other route |
| `busy` | none | a mutating request is running |
| `gone` | none | unknown or expired `session_id`, `scan_id`, `plan_id` |
| `cap_exceeded` | none | the quarantine cap would be passed; the data names the volume and sizes |
| `runtime` | 3 | anything else, with a message |

### 6.5 DTOs

- The RPC types derive `schemars::JsonSchema` (already in the lock file). `xtask gen-dto` writes the schemas to
  `ui/Purge.Client/Schema/` and runs NJsonSchema to write `ui/Purge.Client/Generated/`. `gen-dto --check` fails on
  a difference.
- C# reads with `System.Text.Json` source generation (AOT-safe).
- Fixtures: one JSON file per request, result and notification under `crates/purge-rpc/fixtures/`. A Rust test and a
  C# test both read and write each one and compare.
- Fallback when the generated code is not AOT-clean: hand-written readers as in the stopgap's `EngineDocs`, with
  the same fixture test (section 15).

## 7. Open questions (1-6 answered by the user 2026-11-21, 7 decided by the coordinator)

1. **Per-user apps and elevation.** N5 says the broker must not trust a harvest made at medium integrity. The plan
   says per-user apps need no UAC. Either the UAC prompt also appears for a per-user uninstall (harvest in the
   broker, full evidence), or the per-user harvest stays at medium and its evidence is capped (nothing from it
   reaches Safe or preselection). Which one?
   **Answer (user 2026-11-21):** UAC for every uninstall, per-user included: the harvest runs in the broker, so no medium-made evidence is used.
2. **The release engine links the executor.** The broker needs it, so the 2026-11-15 rule "the release engine
   contains no path into the executor" ends. Keep one executable (as the plan says; the medium `--stdio` process
   then carries executor code it never reaches), or split the broker into its own binary so the medium engine stays
   executor-free?
   **Answer (user 2026-11-21):** A separate broker binary holds the executor; the medium engine stays executor-free and check-deps keeps a rule for it.
3. **Standard-user accounts (over-the-shoulder elevation).** Support in M3 (the broker runs as another account and
   cleans the caller's profile through `HKU\<SID>`), or refuse with a clear message and defer to M4, where the plan
   already has the trap?
   **Answer (user 2026-11-21):** Refuse with a clear message (needs an administrator account) and defer to M4.
4. **Code signing route** (ENGINE_PLAN 11.3 item 4) is still open. It decides whether the caller check can verify
   a signature instead of only a path, and it affects the first-launch gate under Smart App Control.
   **Answer (user 2026-11-21):** Path check now (caller must run from the admin-only install directory); signature check added once a certificate exists.
5. **Closing apps and Explorer.** M2 never closes, stops or restarts anything and never chooses a boot-time
   delete. S2 and S7 show "Close running apps" and "Restart Explorer". Does M3 turn these on (each with consent), or
   ship them report-only and move them later?
   **Answer (user 2026-11-21):** Report-only in M3: the UI names what is locked and what to close; Purge closes, restarts and schedules nothing.
6. **`SeRestorePrivilege` for undo's owner restore (R8b M1).** The plan says Purge never raises its own access for
   deletes. Allow the privilege for the one undo step that puts an owner back, or keep the known limit?
   **Answer (user 2026-11-21):** Allow `SeRestorePrivilege` in the broker only around the owner-set call of undo, dropped right after.
7. **Reuse of the stopgap UI.**
   **Answer (coordinator 2026-11-21):** Reuse. `ui/` starts from the tree of 0d9c008 (the later of the two
   branches on the delete path; 5d7df3c is its scan-only sibling). It comes in by file copy
   (`git checkout 0d9c008 -- ui`), not by merge: the branch also changed the engine.

   | Kept | Dropped |
   |---|---|
   | Project shape: WinUI component packages 2.6.5, TFM, AOT, unpackaged, custom Main | The one-process-per-verb `CliEngineClient` as the product link (kept only as a test helper against the rig CLI) |
   | Start order: hello and list before XAML; fallback notice | Plans and selections in temp files; the `PurgeSandboxDev` roots; the sandbox title and notices |
   | Shell, navigation, styles, the views of the nine pages, launch markers | Home, Footprint, Startup, Assistant, command palette, inline Ask pages |
   | Model shapes and `EngineDocs` readers, until M3-GEN-DTO replaces them | The engine's `cli/sandbox.rs`, the `sandbox-dev` feature and that branch's `check_deps` rule: not taken |
   | Process lessons: kill-on-close job, drain timeout, cancel | `ConsentPrompt.cs`: its layout and wording are the reference for the broker's dialog, then it is deleted |
   | `Purge.Client.Tests` and its fixtures | `ConfirmHash.cs`: the broker computes the hash; the UI only shows the code |
   | `FakeEngineClient`, as a test double only | Sample data and SAMPLE banners as product behaviour |

   The mockups were refined after 0d9c008, so the views are restyled in the UI packages. `xtask ui-strings` must
   pass on the imported strings before M3-UI-IMPORT merges.

## 7a. Mockup deltas (coordinator, 2026-11-21)

The refined mockups hold; six deltas follow from the answers in section 7 and from what the engine
does.

| # | Mockup page and element | Change for M3 | Reason |
|---|---|---|---|
| 1 | "Uninstall pipeline", button "Close python.exe" next to "python.exe × 2 still running" | Keep the running-process line; replace the button with a hint to close it and a Retry button. In "Safety dial settings", the row "Uninstall: Quiet mode, restore points, running apps" drops "running apps" | Open question 5 answer: report-only |
| 2 | The "Standard user" chip in the title bar on every page | Removed. An "Administrator" chip with a shield shows only when the UI itself runs elevated (setting "Always start as administrator") | Open question 3 refuses standard-user accounts, so "Standard user" would read as the account type |
| 3 | "Consent prompts", variant A (Win32 TaskDialog) | Built, as ENGINE_PLAN 9 says. Variant B (WinUI take) is not built. Variant C ("type to confirm", "Remove 5.8 GB for good", items without undo removed at once) is out of M3: items that cannot go to quarantine (no undo, or over the quarantine cap) are reported in the plan and not offered for removal | The M2 executor quarantines everything; a no-undo delete path is new risk with no gate |
| 4 | "Uninstall pipeline" Safety net "Restore point made at 04:12", and the "Quarantine vault" per-volume limit "1.8 GB of 10 GB" | Keep both. The executor's prepare step already requests a restore point per setting (default high-risk only, ENGINE_PLAN 7.7, `crates/purge-exec/src/execute.rs` step 8); the line shows only when one was made. The cap is min(10 GB, 5 % of the volume) (ENGINE_PLAN 7.8 size cap); the UI shows the real cap, not a fixed 10 GB | The plan already holds both, so the mockup reads true |
| 5 | "Removed outside Purge" banners ("Today: Programs", "Programs, refined", "Tidiness home": Notion and Slack) | Shown only for a program whose fingerprint was stored before it was removed (the per-user/machine fingerprint store, ENGINE_PLAN 8). Without one, the program is listed as removed with no leftover count | ENGINE_RESEARCH notes that external uninstalls without a stored record are unattributable |
| 6 | The 22 pages in the mockup | Nine pages in M3, eight later, five explorations (the table below) | M3 covers S1, S2, S3, S7 and the shell; the rest are later or superseded |

Scope of the 22 pages:

| Page | M3 status |
|---|---|
| "Programs, refined" (S1) | In M3 |
| "Leftovers, refined" (S3) | In M3 |
| "Uninstall pipeline" (S2) | In M3 |
| "Consent prompts" variant A | In M3 |
| "Time scrubber" | In M3 as the History & undo screen, but without the drag marker (a plain list with Restore) |
| "Quarantine vault" | In M3 |
| "Safety dial settings" (S7) | In M3 |
| "Snapped narrow" | In M3 (narrow layout) |
| "High contrast" | In M3 |
| "Command palette" | Later, not M3 |
| "Tabs in the title bar" | Later, not M3 |
| "One-at-a-time triage" | Later, not M3 |
| "Drop target" (portable apps) | Later, not M3 |
| "Before and after diff" | Later, not M3 |
| "Tidiness home" | Later, not M3 |
| "Footprint map" | Later, not M3, already a future idea |
| "Inline assistant" | Later, M6 |
| "Today: Programs" | Exploration, not planned (superseded by the refined page) |
| "Programs as weight cards" | Exploration, not planned |
| "Leftovers in three lanes" | Exploration, not planned |
| "Autopsy rings" | Exploration, not planned |
| "Ownership graph" | Exploration, not planned (its "shared with Thunderbird" fact is shown as text in the Leftovers detail pane instead) |

The per-user uninstaller itself still runs at medium with the user's token even though the queue asks
for one admin prompt (ENGINE_PLAN 6, line about never becoming an elevation vehicle); the broker only
harvests and executes the leftover plan.

## 8. Consent dialog (variant A)

A Win32 `TaskDialogIndirect` (common controls v6) shown by the broker on its own thread. All text is built in the
broker from the `BoundPlan` and the broker's own inventory. English only in M3. The strings are Rust literals, so
`xtask ui-strings` covers them.

### 8.1 Quarantine variant (`plan.execute`)

| Part | Content |
|---|---|
| Window title | "Purge security prompt" |
| Icon | shield |
| Main instruction | "Move 22 leftovers of Mozilla Firefox to quarantine?" |
| Content | Counts and size per group: files and folders, registry, associations, shell and COM, services and tasks, firewall rules, packages, privacy traces. One line "20 chosen by Purge as safe, 2 ticked by you". "You can restore everything from History & undo until 2026-12-21." A restore-point line only when one will be requested. |
| Attention list (in the content, never collapsed) | Every item that is user data, every item the user ticked that was not preselected, every item over 1 GB. Each with path, kind, band, size and a ⚠ mark. |
| Expanded information | The other items: the first 100 paths, then "and N more of the same kinds". |
| Verification box | "I reviewed the items marked ⚠". Shown when the attention list is not empty. The primary button is disabled until it is ticked (`TDM_ENABLE_BUTTON` from the callback). |
| Buttons | "Move 22 items to quarantine" (custom id 100) and Cancel. Cancel is the default. Esc, Alt+F4 and the close box mean Cancel. |
| Footer | "Shown by the administrator part of Purge. Code A1B2-C3D4." |

Rules:

- The attention list is never cut. Over 40 entries it continues on further pages (`TDM_NAVIGATE_PAGE`), 40 per page,
  with "Next" and "Back". The primary button exists only on the last page.
- Items the M2 executor cannot quarantine, or over the quarantine cap, never reach the dialog (7a delta 3): they
  are refused at `plan.create`.
- No hyperlinks, no command links, no radio buttons, no timeout answer, no owner window.
- Names and paths are escaped as in T12.
- Foreground: the UI calls `AllowSetForegroundWindow(broker pid)` before `plan.execute`; the broker calls
  `SetForegroundWindow` on `TDN_CREATED` and flashes the taskbar button if that fails. The dialog opens on the
  monitor of the cursor.
- The broker sends `consent.shown` when the dialog is up. The UI then shows "Confirm in the Purge security prompt"
  and the code.
- The dialog content comes from a pure function `consent::view(&BoundPlan, &Facts) -> ConsentView`. Unit tests check
  the view; the Win32 layer only draws it.

### 8.2 Other variants

| Variant | Request | Differences |
|---|---|---|
| Restore | `undo.run` | "Restore 22 items of Mozilla Firefox?" Lists items that will overwrite or conflict as attention items. Button "Restore 22 items". |
| Recover | `journal.resume`, `journal.rollback`, `journal.retry_held` | Names the interrupted session, its time and "37 of 52 done". Button "Finish the cleanup", "Roll the cleanup back" or "Try the held items again". Attention list: the items still to be changed that are user data. |
| Purge | `quarantine.purge` | Icon: warning. "Delete 41 expired items for good? This cannot be undone." Every item and every backup file is named, in pages, never cut. User-data items are not in this dialog: each gets its own dialog, one item per dialog (DECISIONS 2026-11-16). Button "Delete 41 items for good". |
| Delete now | `quarantine.purge` (ids of quarantined items that are not due) | Icon: warning. "Delete 3 quarantined items now, before their retention ends? This cannot be undone." The summary adds: "This is before the retention date. Until then Purge keeps these items, and Undo can put them back. Once they are deleted here, Undo and History can no longer restore them." Every item is named, in pages, never cut; never a backup. User data: one item per dialog ("Delete this user data now, before its retention ends? This cannot be undone."). Button "Delete 3 items now, for good". Its confirmation code is never the purge dialog's (DECISIONS 2026-11-23). |
| Delete backups now | `quarantine.purge` (ids of backups that are not due) | Icon: warning. "Delete 3 registry backups now, before their retention ends? Undo can then no longer restore these registry changes. This cannot be undone." The summary adds: "These backups are what Undo restores the registry, service and task changes of the cleanup from. This is before their retention date; until then Purge keeps them. Once they are deleted here, Undo and History can no longer undo these changes: what the cleanup removed there stays removed." Every backup is named with the change it would undo and every backup file ("Delete the backup of: "HKLM\SOFTWARE\Vendor" · backup file "reg\000003.regbackup.json""), in pages, never cut; never a quarantined item. A user-data op: one backup per dialog. Asked last, and not at all when the request's "Delete now" dialog was cancelled. Button "Delete 3 registry backups now, for good". Its confirmation code is never the purge dialog's nor the "Delete now" dialog's (DECISIONS 2026-11-24). |
| Quarantine, then delete | `plan.execute {delete_after: true}` | Two dialogs, never one. First the Quarantine variant unchanged (same code), with one more summary line: "You asked to delete instead of keeping in quarantine: after the move, a second prompt names the quarantined files and asks whether to delete them for good. Nothing is deleted without it, and this prompt approves the move only." Then, once the run is recorded, the Delete now variant over exactly the quarantined items of that run's session (user data one item per dialog). Cancel of the second keeps everything in quarantine (DECISIONS 2026-11-24). |

## 9. Launch gates and benches

### 9.1 Gates (ENGINE_PLAN 1.3, unchanged until 9.3 runs; the harvest row is relative since 2026-11-23)

| Metric | Gate |
|---|---|
| First Rendering tick, full S1 skeleton | at most the bare-WinUI control + 60 ms p50, same run; absolute guard 360 ms p50, 420 ms p90 |
| Names visible (presented frame with rows), primary | 400 ms p50, 460 ms p90 |
| Icons visible, warm icon cache | 1 s; a cold cache is reported |
| First launch after install or update, Defender on | 1.2 s p50 over 5 fresh copies |
| Cold after reboot, bare metal | 1.0 s p50 on the dev host, N at least 5 |
| VM | functional only; WARP numbers reported |
| Harvest complete after the UAC click, VS Code | at most 2x the bare registry-walk floor measured on the same machine in the same run; absolute sanity cap 20 s |
| Post-uninstall scan, cold broker | 10 s; first progress within 100 ms |
| S3 page open, 2,000-item fixture | reported, no gate yet |

No broker and no UAC at launch. The baseline build never runs at launch, only in a started broker.

**How the engine rows are measured (gate G12; DECISIONS 2026-11-22, `purge_rpc::timing`).** The broker takes
timing marks, each in ms since the broker *process was created* (`GetProcessTimes`; monotonic after one wall-clock
offset) plus the wall clock. They come back in an optional `timings` member of the results of
`uninstall.prepare`, `leftovers.scan`, `plan.create` and `plan.execute`, and as one Application-log line per mark
(source `Purge`, event id 100), which `vm/guest/broker-timings.ps1` collects and `cargo xtask broker-timings`
reduces.

| Row | Measured as |
|---|---|
| Harvest complete after the UAC click | `harvest_complete` of `uninstall.prepare`, ms since process creation. The broker process is created when the user clicks Yes, so this counts the start checks, the UI's connect, server check and hello (`pipe_connected`), and the harvest itself (`harvest_start` to `harvest_complete`, reported too). The UI's launch-to-connected (from its `ShellExecuteExW` call) is not used: with UAC on it holds the human's click. |
| Post-uninstall scan, cold broker | `scan_complete - scan_start` of the broker's first `leftovers.scan` (the e2e flow starts one broker per app, so its scan is a cold one) |
| First progress within 100 ms | `first_progress - scan_start`; `first_progress` is taken when the request's first `scan.progress` line has been written to the pipe |

Marks never fail or change a request: a mark the clock cannot give is left out.

**The walk floor of the harvest row (DECISIONS 2026-11-23, "G12 harvest row relative to the walk floor").** The
harvest walks the whole reference scope once (ENGINE_PLAN 5.5: `HKLM\SOFTWARE`, the services and the machine
environment of the current control set, the user's `Software`, `Environment` and `_Classes`; about 520,000 keys on
the dev host), and that walk is bound by the registry itself: an absolute 3 s cannot be met on any machine we have,
whatever the engine does with what it reads. The row therefore compares the harvest with what the same walk costs
on the same machine with nothing done to what is read:

- **Numerator:** `harvest_complete` of `uninstall.prepare`, ms since the broker process was created, as before.
- **Floor:** `purge-engine walk-floor [--runs <n>] [-o <file>]` (document `purge.walk-floor/1`). It builds the scope
  the harvest's reference scan walks for the interactive user (`purge_harvest::refsnap::scope_for_sids`, the function
  the harvest itself calls) and reads it with `purge_index::refscan::bare_walk`: the scan's own walk, through the same
  walker, on the same threads, with the same split and prune list, every key entered, its values read and its subkeys
  listed, and no value tested. It writes nothing but its document. Three walks by default; `floor_ms` is the shortest
  (a floor is a lower bound, and the shortest walk is the strictest choice for the gate). Each walk is reported with
  its keys, values, pruned keys, links and unreadable keys, so a floor of another scope shows.
- **Where it is taken:** in the VM run of `m3-e2e`, by the guest's `finish` phase, elevated like the broker, with the
  installed release engine (the engine the broker was built with), after the app's harvest:
  `<app>\guest\walk-floor.json`. The scorer fails the row when the document is missing, has no positive `floor_ms`
  or is not from an elevated engine.
- **Gate:** `harvest_complete <= 2 x floor_ms` and `harvest_complete <= 20,000 ms`. The factor leaves the harvest as
  much again as the walk for everything else it does (start checks, pipe, anchors, indexes, testing every value); the
  cap keeps a machine with a slow floor from passing a harvest nobody would wait for, and bounds a floor that was
  itself disturbed.
- **Why a verb of the release engine and not a `rig-exec` verb, an xtask or rigtool:** `m3-e2e` installs the release
  engine and broker (`install.ps1` refuses a `rig-exec` engine), so a `rig-exec` verb is not on the VM in the run that
  needs it; xtask runs on the host; rigtool is a project of its own with its own registry reader, so its walk would be
  another walk (other opens, other threads, and a copy of the scope and prune list to keep equal by hand). The
  engine's verb is the harvest's walk by construction. It adds no capability: it reads keys `harvest` and
  `baseline build` already read, with the caller's rights, and prints counts and times.
- Host, unelevated, 8 logical CPUs, 518,574 keys and 781,463 values: floor 6.0 s (three walks within 30 ms of each
  other), CLI harvest of ten installed apps 7.7 to 10.6 s, ratio 1.3 to 1.8. `PURGE_TIMING` must not be set for the floor (a metered walk
  is slower; the verb warns).

### 9.2 `xtask bench-launch`

- Runs the published `Purge.exe` and the bare-WinUI control in turn, N = 21 each, first run dropped.
- Reads the markers of `PURGE_BENCH_OUT`: module init, `OnLaunched`, window constructor, first Rendering tick,
  first presented frame (`DwmFlush` after the first tick), first realized row, engine ready, list reply.
- Writes `bench/launch/<date>-<host>.json` with p50, p90, the deploy flavour, the WinAppSDK version and the host.
- Fails on a gate breach or on a p50 more than 10 % over the last file of the same host.
- Not part of `xtask ci` (it needs a published build and a quiet machine). It is a gate step.
- `--first-launch` copies the publish folder to 5 fresh directories and times launches 1 to 5 in each.

### 9.3 S1 skeleton bench (package M3-BENCH, wave 2)

It runs before any screen package. The skeleton is the imported shell cut to the first-frame content of ENGINE_PLAN 9.2 item 3:
Mica, title bar with the search box, the rail and command row as plain Buttons, the virtualized list with 40 px rows.
It starts the real `purge-engine --stdio`. Until M3-STDIO exists, a stub answers `engine.hello` and one
`programs.batch` of 300 rows after 20 ms.

| Result | Then |
|---|---|
| All of 9.1's launch rows hold on the dev host | the gates are frozen as written; a DECISIONS row records the numbers |
| The skeleton is over the control + 60 ms | try the XamlChangeIds one at a time, then remove first-frame elements; re-bench |
| The absolute guards fail but the relative gate holds | the coordinator re-bases the absolute guards to this host in a DECISIONS row (the plan's numbers are from the earlier dev host) |
| "Names visible" is over its gate by more than 10 % after the steps above | a question for the user, with the numbers |

Cold-after-reboot needs five reboots of the dev host. It is run once, at the gate, with the user's agreement to
the reboots. The iGPU laptop row of the plan is the dev host itself since the rig moved (2026-11-19).

## 10. Screens

All wording is our own. Each page is created lazily, after the first Rendering tick, except the S1 first frame.

| Page (7a name) | Built from | Data | Notes for M3 |
|---|---|---|---|
| Shell | stopgap `MainWindow` | `engine.hello` | Rail: Programs, Uninstall pipeline, Leftovers, History & undo, Quarantine vault, Settings. "Administrator" chip only when elevated (delta 2). No Assistant entry. |
| Programs, refined (S1) | stopgap Programs view | `programs.*`, `icon.batch`, `size.ready`, `inventory.changes` | Tabs Apps, Components, Unnamed, Recent. Buttons: Uninstall; multi-select for a queue. "Force remove", "Modify", "Remove entry" hidden. Details pane. "Removed outside Purge" banner per delta 5: "Check for leftovers" starts the broker and asks `leftovers.stored`. |
| Uninstall pipeline (S2) | stopgap queue view, rewired | `uninstall.prepare`, `uninstall.route`, `uninstall.run`, `uninstall.run_user`, `uninstall.observed`, `leftovers.scan` | UAC on the Uninstall click, for every app (answer 1). Confirm dialog: steps, exact command and signer, Quiet toggle, restore-point choice. No "Close running apps" toggle: the running-process line, a hint and Retry (delta 1). Stepper: record, run, check gone, find leftovers, ready. Error bars: exit code with "Run forced cleanup" and "Retry"; still installed; restart needed (text only). "Restore point made at ..." only when one was made (delta 4). |
| Leftovers, refined (S3) | stopgap review view | `scan.candidates`, `candidate.explain`, `plan.create` | Flattened virtualized list, eight groups, group boxes tick Safe items only. Why lines with tier glyphs. Protected and report-only sections. "Shared with ..." as text in the detail pane. Footer "Move N items to quarantine…". Banner when `baseline.changed` offers a new scan. Items the plan refuses are shown as "cannot be quarantined", unticked. |
| Consent prompts, variant A | section 8 | `consent.shown` | The UI side is one state: "Confirm in the Purge security prompt", the code, and a spinner. |
| Result (part of S3) | new | `plan.execute` result | Moved, already gone, held (with what holds it and "Try again"), failed. "Undo all", "Done". Outcomes of 6.4. |
| Delete instead of keeping (part of S3) | new | `plan.execute {delete_after}` | Footer tick box "Delete instead of keeping in quarantine", off by default and after every move; the button then reads "Move N items, then delete them…". The waiting state names the second prompt when the broker's `delete_after` phase arrives. The result adds one line that says what was deleted for good and what is still in quarantine (DECISIONS 2026-11-24). |
| History & undo ("Time scrubber", no drag marker) | stopgap History view, real data | `history.index` (medium), `history.get`, `undo.run`, `journal.*` (broker) | Sessions newest first: time, app, count, size, days left, state. "Show items" and "Restore" start the broker. Recovery banner with Resume and Roll back. No journal or `.reg` export in M3. |
| Quarantine vault | stopgap vault view, real data | `history.index`, `quarantine.expiring`, `quarantine.purge` | Usage and real cap per volume (delta 4). "Expired" list with "Review and delete…". "Delete now…" per cleanup and, under "Choose items…", per quarantined item, before the retention ends (DECISIONS 2026-11-23). The cleanup's "Delete now…" opens a choice with the tick box "Also delete its registry backups (its registry changes can then no longer be undone)", off each time; ticked, the backups' ids go into the same request and the broker asks for them in a dialog of their own (DECISIONS 2026-11-24). No "Empty quarantine". |
| Safety dial settings | stopgap Settings view | UI settings file in `%LOCALAPPDATA%\Purge\settings.json` | Theme; prefer quiet uninstall; after uninstall: ask or scan; restore point: off, high-risk only (default), always; show weak matches; retention and cap shown read-only; last 10 launch markers; versions and licences. Not shown: running apps (delta 1), start as administrator, packs, other profiles, AI. |
| Snapped narrow | new | none | Under 720 px: the rail collapses to icons, the details pane becomes a page, list columns drop to name and size. |
| High contrast | new | none | System colours only, no Mica, band pills carry text and a glyph, focus visuals on every control. |

Settings never reach the broker as free values. `quiet` and `restore_point` travel as a boolean and an enum in the
requests. The dialog states the restore-point choice. The cap function moves to `purge-model` as a pure function,
so the medium engine and `purge-exec` share it.

Per-user runner (medium engine): `pipeline::uninstall` with the user's token, inside a job, waiting for the tree
and the ARP entry as today. `programs.patch`: MSI properties, Burn links and AppX badges follow the raw ARP batch.
Icons: viewport-first batches of 24 px BGRA; the UI keeps one atlas file keyed by path and modification time.

## 11. Tests

### 11.1 In `xtask ci` (host, no admin, no VM)

| Step | What |
|---|---|
| existing 1-12 | unchanged; the clippy and test lists gain `purge-broker` |
| `purge-rpc` tests | framing, limits, unknown fields, the capability table per transport, fixtures round trip |
| `purge-broker` library tests | in-memory transport and a scripted `Consent`: the state machine of sessions, scans and plans; ids of another scan; `busy`; decline does nothing; pipe loss during a run; the consent view (escaping, paging, 5,000 items, attention rules) |
| request-shape test (T3) | walks the schema of every broker request type: only id newtypes, enums, booleans, integers |
| pipe tests | a real named pipe, unelevated: first instance, DACL, wrong client pid, wrong creation time, three failures then exit |
| `check-deps` rule 4, rewritten | (a) purge-exec is linked by purge-broker, and by purge-engine only with `rig-exec`; (b) purge-broker's tree has neither `fault-inject` nor `test-support`; (c) purge-engine's default tree has neither purge-exec nor `purge-win/write`; (d) nothing depends on purge-broker; (e) `SeRestorePrivilege` appears in one function of `purge-win` with one caller in `purge-exec` |
| `gen-dto --check` | generated C# is current |
| `ui` step | `dotnet build` and `dotnet test ui/Purge.Client.Tests`. The SDK is looked up on PATH, then in `C:\Program Files\dotnet`. Without an SDK the step prints `skipped`, like `ui-strings`. `xtask ci --require-ui` fails instead; the gate uses it. |
| `ui-strings` | already walks `ui/**/*.cs` and `ui/**/*.xaml` |

The scripted `Consent` exists only under `cfg(test)`. The binary has one `Consent`: the TaskDialog.

### 11.2 VM rig

The rig agent runs elevated. An elevated driver can click the consent dialog; a medium one cannot. Both facts are
used.

| Mode | UAC | What it proves |
|---|---|---|
| `m3-broker` | silent (`ConsentPromptBehaviorAdmin=0`, the rig default) | T2, T5, T6, T7: every refusal of 3.3 and 3.4 with a real elevation; nothing is written under the data root in any refused case |
| `m3-consent` | silent | T1: a medium process tries `SendInput`, `PostMessage(BM_CLICK)`, `WM_COMMAND`, UI Automation Invoke and Toggle on the dialog; the journal stays empty. Control: the same driver at high integrity succeeds. |
| `m3-uac` | **on**: `ConsentPromptBehaviorAdmin=5`, `PromptOnSecureDesktop=1`, new snapshot `m3-uac-on` | "No" at the prompt gives the cancelled bar (error 1223) and no broker. "Yes" gives the full flow. A standard-user account with administrator credentials typed is refused (T8). The host answers the secure desktop with `VBoxManage controlvm ... keyboardputscancode` and keeps a screenshot. |
| `m3-e2e` | silent | UI automation from Uninstall click to undo on: VS Code (system), VS Code (user, medium route), Git, Firefox with Thunderbird installed, Notepad++, 7-Zip, and one M1b app with a service or task. Per app: the executed set equals the preselected set of the rig CLI plan on the same snapshot; collateral 0; undo through the UI; `undo_fidelity` 100 %. |
| `m3-owner` | silent | R8b M1: a service undo interrupted and resumed restores the recorded owner; the privilege is off before and after (T10) |
| `m3-recover` | silent | power-off during execute; the next start shows the banner; Resume and Roll back through consent |
| `m3-clean-start` | default | Clean-Pro without .NET, WinAppSDK runtime or VC++ redistributable: `Purge.exe` starts and shows names; WARP numbers reported |

Rules of the rig stay: one VM at a time, official downloads only, the clone and UT are never touched.
M3-RIG-UAC (wave 1) checks early that the scancode route works. If it does not, `m3-uac` becomes a manual
checklist of six steps with screenshots.

### 11.3 Manual

- The `SendInput` test of the exit criteria, once by hand on the VM with UAC on, besides `m3-consent`.
- Cold-after-reboot launches on the dev host (9.3).
- A keyboard-only and a Narrator pass over the nine pages and the dialog.

## 12. Gate criteria (`docs/M3_GATE.md`)

| # | Criterion | Evidence |
|---|---|---|
| G1 | `xtask ci --require-ui` passes, elevated and unelevated | host logs |
| G2 | Launch gates of 9.1 as frozen by 9.3; first-launch; cold after reboot | `bench/launch/*.json` |
| G3 | Broker refusals: every row of `m3-broker` refuses and writes nothing | rig rows |
| G4 | Consent cannot be driven from medium integrity: `m3-consent` 0 of N attempts, control succeeds; the manual test agrees | rig rows, screenshots |
| G5 | UAC on: cancel, accept, standard-user refusal | `m3-uac` rows, screenshots |
| G6 | End to end: 7 apps, executed set equals the preselected set of the rig plan, `danger` 0, `collateral` 0, `undo_fidelity` 100 % | `m3-e2e` rows scored by the M2 and M1b scorers |
| G7 | Medium route: the per-user uninstaller ran at medium integrity; a broker-route program is refused by the medium engine and the reverse | rig rows |
| G8 | R8b M1 closed: owner restored after a resumed undo; privilege scope holds | `m3-owner` |
| G9 | Recovery and expiry through consent; user-data items one by one; a declined dialog changes nothing | `m3-recover`, purge rows |
| G10 | BL-R1 S4 closed: planted environment directories are ignored; a copy outside the system volume or in a user-writable directory refuses to start | `m3-broker` |
| G11 | Starts on clean Windows | `m3-clean-start` |
| G12 | Engine timing: harvest at most 2x the walk floor of the same run and 20 s (9.1), scan 10 s, first progress 100 ms | broker timings and `walk-floor.json` in the e2e rows |
| G13 | Regression: the M1b scan gate and the executor gate still pass on the M3 commit (rig CLI, `rig-exec`) | existing gate scripts |
| G14 | Reviews R1, R2, R3 have no open blocker; every finding has a disposition | `docs/reviews/m3/` |

The M3 gate runs after BL-GATE (HANDOFF-baseline). M3 code that does not touch the baseline can start before it.

## 13. Risks

| Risk | Mitigation |
|---|---|
| The S1 skeleton misses the launch gates on the laptop | M3-BENCH runs in wave 2, before any screen package; the steps of 9.3 |
| The secure desktop cannot be answered from the host | M3-RIG-UAC in wave 1; manual checklist as fallback |
| UI Automation of a WinUI AOT app is flaky in the VM | automation ids on every control the e2e uses; `vm/guest/ui.ps1` coordinates as fallback; retries are counted and reported |
| NJsonSchema output is not AOT-clean | fixture round trip in wave 3; hand-written readers as fallback |
| The broker pulls `cli` code through the `purge-engine` library | accepted for M3; `check-deps` proves no `rig-exec`; a `purge-pipeline` crate is a later clean-up (section 15) |
| A `--workspace` build unifies `purge-win/write` into the engine | release script builds per package; `check-deps` (c); the install self-test checks the engine's imports |
| TaskDialog paging is awkward for hundreds of attention items | the review page warns over 200 ticked attention items and suggests smaller steps; the dialog still shows all |
| The dialog does not come to the foreground | `AllowSetForegroundWindow`, flash, and the UI's waiting state names the prompt |
| A second UAC prompt after the 10-minute idle exit annoys | the UI says why; the re-scan from the stored fingerprint keeps the ticks |
| Smart App Control or SmartScreen blocks unsigned binaries | reported in `m3-clean-start`; signing is answer 4, later |
| The baseline branch moves `pipeline.rs` while M3 edits near it | M3 adds files and calls; edits to `pipeline.rs` only in M3-ENGINE-OUT, after BL-GATE merges |
| C: fills during parallel builds | the build environment of HANDOFF-baseline; delete a finished worktree's `target/` |
| WinAppSDK 2.x servicing ends 2027-04-29 | scheduled upgrade and re-bench task after the gate |
| English-only dialog on a non-English Windows | accepted for M3; common buttons are avoided so no mixed language appears except "Cancel" drawn by us |

## 14. Packages, waves, reviews

Details, files, rules, tests and acceptance per package: `docs/M3_DESIGN.json`. Model routing: critical = Fable
medium (or Opus high plus a Fable review); high = Opus high; medium = Opus medium; trivial = Sonnet; VM campaigns
under a Haiku babysitter.

| Wave | Id | Importance | What |
|---|---|---|---|
| 1 | M3-S0 | trivial | Manifests, empty modules and stub files so later waves share no file |
| 1 | M3-UI-IMPORT | medium | `ui/` from 0d9c008, pruned (question 7); builds and starts on sample data |
| 2 | M3-BENCH | high | `xtask bench-launch`, the bare control, the S1 skeleton bench; gates frozen |
| 1 | M3-RIG-UAC | high | Rig spike: UAC-on snapshot, scancode answer, UIPI probe with a dummy elevated dialog |
| 2 | M3-RPC | critical | `purge-rpc`: framing, limits, table, capability sets, errors, request and result types |
| 2 | M3-DEPS | critical | `check-deps` rule 4 rewritten for the broker; release build commands |
| 2 | M3-HARDEN | critical | BL-R1 S4: elevated directories, system-volume rule, DLL search; engine and broker |
| 2 | M3-WIN-PIPE | critical | `purge-win`: pipe server, client and server identity, process identity, token facts |
| 2 | M3-WIN-TASKDLG | high | `purge-win`: TaskDialog wrapper with pages, verification box and button enabling |
| 2 | M3-WIN-PRIV | critical | Scoped `SeRestorePrivilege` and its one call site in undo (R8b M1) |
| 3 | M3-STDIO | high | `purge-engine --stdio`: hello, programs, sizes, changes, history index |
| 3 | M3-ICONS | medium | Icon batches in the engine, atlas cache in the UI |
| 3 | M3-RUNNER | high | `uninstall.route`, `uninstall.run_user`, the route and level rules |
| 3 | M3-BROKER-CORE | critical | `purge-broker`: start checks, pipe, handshake, account check, sessions, lifetime, baseline build |
| 3 | M3-GEN-DTO | medium | `xtask gen-dto`, schemas, generated C#, fixture round trip, the `ui` ci step |
| 3 | M3-ENGINE-OUT | medium | Scan output the UI needs: display name, owner program, typed warnings, firewall names |
| 3 | M3-UI-SHELL | medium | Shell, rail, chip, custom Main order, launch markers |
| 4 | M3-BROKER-FLOW | critical | prepare, run, observed, scan, candidates, explain, `plan.create` |
| 4 | M3-CONSENT | critical | Consent view model and the dialog, four variants |
| 4 | M3-UI-CLIENT | high | RPC clients for stdio and pipe, the broker launcher, server check, job object |
| 4 | M3-UI-S1 | medium | Programs page on the real engine |
| 5 | M3-EXEC | critical | `plan.execute`: `execute_bound`, object binding, progress, outcomes, exit rule |
| 5 | M3-UNDO | critical | `history.get`, `undo.run`, `journal.*` through consent |
| 5 | M3-PURGE | critical | `quarantine.expiring` and `quarantine.purge` through the purge dialog |
| 5 | M3-UI-S2 | medium | Uninstall pipeline page |
| 5 | M3-UI-S3 | high | Leftovers page, waiting state, result page |
| 6 | M3-UI-HISTORY | medium | History & undo and Quarantine vault |
| 6 | M3-UI-SETTINGS | medium | Settings page and the settings file |
| 6 | M3-UI-A11Y | medium | Narrow layout, high contrast, keyboard, automation ids |
| 6 | M3-INSTALL | high | `install.ps1`: UI folder, broker, Start-menu shortcut; self-test |
| 7 | M3-RIG | high | Rig modes `m3-broker`, `m3-consent`, `m3-uac`, `m3-owner`, `m3-recover`, `m3-clean-start` |
| 7 | M3-E2E | high | UI automation end to end and its scorer |
| 8 | M3-GATE | gate | All of section 12; writes `docs/M3_GATE.md` |

Review points (Fable, written to `docs/reviews/m3/`):

| After wave | Id | Attack |
|---|---|---|
| 2 | M3-R1 | Reach an Execute method over stdio. Get a path or a document into a broker request. Start the broker from a user-writable place or with planted directories. Connect as a second client or serve a fake pipe. Keep the privilege on after the scope. Break `check-deps` with a feature or a dev-dependency. |
| 5 | M3-R2 | Make the executor run something the dialog did not show. Run a plan of another scan or run one twice. Get a medium-route program run by the broker. Mislead with names or paths in the dialog. Lose a session by killing the UI at each step. Purge a user-data item without its own dialog. |
| 7 | M3-R3 | The UI side of the boundary: the launcher, the server check, what the UI shows when the broker lies or dies. Are the rig modes able to fail (controls)? Is the e2e comparison honest? Gate readiness. |

Each critical package also gets its own Fable review before its wave merges, as in M2.

## 15. Not in M3 (cut or move)

- First to cut if the schedule slips: M3-PURGE. The cap refusal explains itself, and the rig CLI can purge.
- Second: `journal.retry_held` in the UI (held items stay listed; the next run tries them).
- "Always start as administrator": M4. An elevated UI needs a way to run medium-route uninstallers under the shell
  token; M3 refuses those instead.
- Standard-user accounts: M4 (answer 3).
- Closing apps, restarting Explorer, boot-time operations: after M3, with a consent design of their own (answer 5).
- "Empty quarantine", "Force remove" by path, "Remove entry", "Modify", Store tab, pre-harvest cache, the rest of
  S5: M4.
- Journal and `.reg` export from History: M4.
- A `purge-pipeline` crate, so the broker stops depending on the `purge-engine` library: clean-up after the gate.
- Signature check of the caller and of the uninstaller route: when a certificate exists (answer 4).
- Localisation of the dialog and the UI: later.
- WinAppSDK major upgrade and launch re-bench: scheduled before 2027-04-29.
- Hand-written DTO readers instead of NJsonSchema: only if M3-GEN-DTO fails its AOT check.

## 16. Decisions added to DECISIONS.md

- 2026-11-21 (user): answers to open questions 1-6, one row.
- 2026-11-21 (coordinator): mockup deltas, one row.
- 2026-11-21 (coordinator), eight rows from this design:

| # | Decision |
|---|---|
| 1 | Question 7: the UI starts from the `ui/` tree of 0d9c008 by file copy; the CLI transport, the sandbox roots, the C# consent preview, the C# confirm hash and the sample pages go |
| 2 | The broker is `bins/purge-broker`, links the `purge-engine` library and `purge-exec`, has no cargo feature; `check-deps` rule 4 is rewritten; releases are built per package |
| 3 | The broker is the pipe server; each side checks the other; the image path is `<broker's own directory>\Purge.exe` |
| 4 | The broker reads no directory from the environment and runs only from an admin-only directory on the system volume; it refuses a client of another account; `SeRestorePrivilege` is scoped to one thread and one call site |
| 5 | "Always start as administrator" moves to M4; an elevated UI gets the chip; medium-route uninstallers run only at the shell's level; the broker trusts only its own verify-gone |
| 6 | Broker lifetime (3.6) and consent content (section 8): attention items never cut, Cancel default, no owner window, escaped text, a short code in both windows |
| 7 | M3 scope cuts of 5.2; expired-item purge is in but first to be cut; a queue runs one app after the other |
| 8 | Tests and gates: the UAC-on mode answered by host scancodes, the `ui` ci step with `--require-ui` at the gate, seven e2e apps, launch gates frozen by the S1 skeleton bench, `install.ps1` gains the UI, the broker and one shortcut |

## 17. ENGINE_PLAN lines that now disagree

ENGINE_PLAN.md is not edited here. A later edit should follow this list.

| Line | ENGINE_PLAN says | M3 design |
|---|---|---|
| 21 (D2), 138, 144, 204, 226, 287, 1439 | the broker is the engine exe with `--broker` | a separate `purge-broker.exe` (answer 2); `purge-engine --broker` is removed from the CLI |
| 137 | the medium engine does per-user read scans | no scan runs at medium (N5, N6) |
| 151 | the UI creates the pipe | the broker creates it (3.3) |
| 152 | image path `%ProgramFiles%\Purge\Purge.exe` | `<broker's own directory>\Purge.exe`, directory checked by 3.4 |
| 161, 1090, 1297 | "always start elevated" setting | not in M3 (section 15) |
| 166, 172 | the dialog lists agent-origin, Reversibility-None and boot-time items | none of these can be in an M3 plan |
| 227, 258 | a release CLI `exec` opens the consent dialog | the release CLI still exits 5; consent exists only in the broker |
| 238 | `uninstall.prepare`: per-user entries are routed to the medium engine | the harvest is always in the broker; only the uninstaller is routed |
| 240 (`leftovers.scan`, set Read) | available on every transport | broker pipe only |
| 383 | `WM_CLOSE` first, termination with consent | report only (answer 5) |
| 925, 956, 957, 958 | close app, stop service, restart Explorer; boot-time move; boot-time delete | report only; held items are retried (answer 5) |
| 1138, 1158 | "Standard user" / "Administrator" chip | "Administrator" only, when elevated (delta 2) |
| 1189 | per-user apps need no UAC | UAC for every uninstall (answer 1) |
| 1194, 1298, 1321, 1322 | "Close running apps" toggle, setting and dialog; "Restart Explorer" dialog | not built (answer 5, delta 1) |
| 1276 | the dialog shows "the hash" | a short code from the confirm hash (6.3) |
| 1288 | "Empty quarantine…" | not in M3 |
| 1290-1304, 1439, 1440 | Settings is S5 and belongs to M4 | a reduced Settings page is in M3 (7a) |
| 1318, 1319 | "Force remove" and "Remove entry" dialogs in S7 | M4 |
| 3.3 header | sets Read, Propose, Execute | a fourth set, UserRun (6.2) |

## 18. Checks on this host

| Check | Result (2026-11-21) |
|---|---|
| `Microsoft.WindowsAppSDK.WinUI` 2.6.5 and `.Runtime` 2.6.5 restore with the .NET SDK 10.0.404 at `C:\Program Files\dotnet\dotnet.exe` (not on PATH) | **Restores**, 11.7 s, exit 0. Project: `net10.0-windows10.0.19041.0`, x64, `WindowsPackageType=None`, self-contained, `PublishAot`. It also pulled `.Base`, `.Foundation`, `.InteractiveExperiences`, WebView2, the ILCompiler and the Windows SDK reference packs. The package folder was 1.4 GB; it was deleted. |
| Build or publish of that project | not run (restore only) |
| A warning "An issue was encountered verifying workloads" | printed by the SDK; restore still succeeded |

For C: space, UI builds should share one NuGet package folder (`NUGET_PACKAGES`), not one per worktree.

## 19. Questions left for the user

None blocks the start of M3. Two points need the user later:

1. The cold-after-reboot bench needs five reboots of the laptop at the gate.
2. Code signing (answer 4) stays open: it needs a certificate, which costs money or an external account. Until
   then the UAC prompt says "unknown publisher" and Smart App Control may block a first launch.
