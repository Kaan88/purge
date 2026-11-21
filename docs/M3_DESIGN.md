# M3 design: UI + broker (DRAFT, paused 2026-11-21)

Status: **draft, unfinished.** The design work was paused while the inputs were still being read. Sections marked
TODO are not written. Nothing here is decided yet: no rows were added to `docs/DECISIONS.md`, and
`docs/M3_DESIGN.json` does not exist yet. Section 9 lists what the resuming session must still read and check.

Milestone row (ENGINE_PLAN.md 11.1): WinUI shell (S1, S2, S3, S4, S7), custom Main, launch bench + S1 skeleton
bench, `--broker` (pipe, identity, consent TaskDialog), per-user runner in the medium engine, `programs.patch`, icon
batches. Exit: the launch gates of 1.3, end-to-end on the M1 apps via UI automation, broker consent cannot be driven
from medium IL (manual `SendInput` test), starts on clean Windows.

## 1. Where the code stands (read so far)

- `crates/purge-rpc` holds only `EngineHello` and the baseline status types. No framing, no method table, no
  capability sets. M3 writes all of it.
- `bins/purge-engine`: `--stdio` and `--broker --pipe p --parent 1 --parent-ctime 2` parse and exit 1
  (`NotImplemented`). Executor verbs exit 5 (`NeedsConsent`) unless built with `rig-exec`. `main.rs` takes the
  baseline directory from `PURGE_KB_DIR` and the data root from the `ProgramData` environment variable.
- `tools/xtask check-deps` rule 4: only purge-engine links purge-exec, and only with `rig-exec`; a default build
  links the executor into nothing. **M3 has to change this rule**, because the broker is the release path into the
  executor (DECISIONS 2026-11-15, `--confirm` row, "Reverse if: M3").
- `purge-exec` already has what the broker calls: `plan_in::bind` / `confirm_hash` / `selection_hash`,
  `execute::execute`, `undo::undo`, `recover::{pending, resume, rollback, retry_held}`,
  `expiry::{expiring, purge, PurgeConsent}`, `storage::StorageRoots::installed`.
- `ui/` holds a README only. Prior art, not merged: `origin/worktree-agent-a7c285be2b9791f54` (0d9c008, about
  10,900 lines: `Purge.App`, `Purge.Client` with a CLI engine client, `Purge.Client.Tests`, an engine
  `cli/sandbox.rs`, a changed `check_deps.rs`) and the later `origin/ui-alpha` (5d7df3c, about 14,400 lines, scan
  and review without deletes). Only the file lists were read. TODO: read both and decide what to reuse.

## 2. Inherited requirements (collected, to be turned into packages)

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

## 3. Architecture (draft)

Three processes, as in ENGINE_PLAN 3.1:

- `Purge.exe` (medium, `asInvoker`): UI only. Starts `purge-engine --stdio` from the custom Main before XAML.
- `purge-engine --stdio` (medium): inventory, icons, sizes, `inventory.changes`, per-user uninstallers under the
  user's token. Capability sets Read and Propose. It never produces a document the broker trusts (N5).
- `purge-engine --broker` (high, one UAC prompt per use): harvest, machine-scope uninstall, index, scan, plan,
  consent dialog, execute, undo, expiry purge, journal recovery. Exits after an execute or undo completes, or after
  10 minutes idle, or when the parent handle is signalled.

Draft position on what runs where (to be confirmed, see open questions 1 and 2):

- Every harvest, scan and plan that can lead to a deletion runs in the broker, also for per-user apps. The medium
  engine only runs the per-user uninstaller. Consequence: a per-user uninstall that should be followed by a cleanup
  asks for elevation at the Uninstall click, so the harvest happens before the uninstaller runs.
- The broker holds sessions in memory (`session_id`, `scan_id`, `plan_id`). The UI sends ids and selected candidate
  ids, never targets, paths or documents.
- Plan binding: `plan.create` binds the scan and selection with `plan_in::bind`; the dialog is rendered from the
  `BoundPlan`; "Move N items" calls the executor with the same `BoundPlan` object. No re-read from disk, no
  second derivation between consent and execution.

TODO: pipe creation and SDDL, the handshake, the caller identity check (pid + creation time + image path; signature
check once signing exists), "always start elevated" mode, standard-user (over-the-shoulder) elevation and which
SID the per-user scope follows, lifetime and idle exit, how `rig-exec` and the consent path coexist in one binary.

## 4. Threat model for the broker (draft)

Trust statement kept from the plan: a same-user process with a shell is the user. The broker is defence in depth
against automation and against a standard user, not a sandbox for the administrator's own account.

| Threat | Draft answer | State |
|---|---|---|
| A medium-IL process of the same user drives the consent | The dialog is a TaskDialog owned by the high-IL broker; UIPI blocks input from lower IL. Test: manual `SendInput` and UI Automation from medium IL, with UAC at its default | to detail |
| A medium process starts its own broker and talks to it | The broker accepts one client: pid and creation time from the command line, image path under the install directory. Even an accepted client can only send ids; every delete still ends in the dialog | to detail |
| Plan tampering between consent and execution | The confirm hash covers plan and selection; the executor runs the in-memory `BoundPlan` the dialog was rendered from; the act-time gates re-validate each item | to detail |
| Pipe squatting | Random 128-bit name, `FILE_FLAG_FIRST_PIPE_INSTANCE`, SDDL for the user's SID and SYSTEM, `PIPE_REJECT_REMOTE_CLIENTS`. The UI is the server, so the UI must also verify the connecting broker (elevated, expected image) before it shows anything it says | to detail |
| DLL planting next to the binaries | Install directory admin-only (`install.ps1`); the broker refuses to run when its own directory is not admin-only writable; static CRT; `SetDefaultDllDirectories(SYSTEM32)` first thing in `main` | to detail |
| Directories taken from the environment (BL-R1 S4) | Elevated: known-folder API for the data root, `PURGE_KB_DIR` ignored outside rig builds, fixed local volume required | requirement fixed, package to write |
| Documents made at medium integrity (N5) | The broker accepts no fingerprint, scan or plan from the client | see open question 1 |
| A standard user gets an elevated delete without consent | Needs an administrator's credentials at UAC and then the dialog. TODO: over-the-shoulder case, whose profile is cleaned | TODO |

TODO: UAC prompt spoof and command-line visibility in the UAC dialog, handle inheritance into the broker,
TOCTOU on the image-path check, the "always elevated" UI (no UIPI boundary between UI and broker then), denial of
service (a client that floods or stalls the pipe), what the dialog shows when there are thousands of items.

## 5. Sections not written

- TODO: Scope in and out (S5 and S6 are out; what of S7 is in depends on open question 5).
- TODO: RPC additions (framing, capability sets per transport, the method table against ENGINE_PLAN 3.3, progress
  notifications, cancellation, error codes mapped from the CLI exit codes).
- TODO: Launch-time gates, `xtask bench-launch`, the S1 skeleton bench, first-launch and cold-boot protocols.
- TODO: Screens S1, S2, S3, S4, S7 at build level; the consent TaskDialog content.
- TODO: Per-user runner in the medium engine; `programs.patch`; icon batches and the atlas cache.
- TODO: DTO generation (`xtask gen-dto`, NJsonSchema), `ui-strings` over `ui/**`, `xtask ci` additions.
- TODO: Test strategy (unit, pipe and identity tests, VM rig with UAC on, UI automation end to end on the M1 apps).
- TODO: Gate criteria, risks, the WinAppSDK upgrade task before 2027-04-29.
- TODO: Work packages, waves, review points, cut_or_move (and the JSON file).

## 6. Draft package list (names only, not yet sized or ordered)

Critical (Fable writes or reviews): RPC framing and capability sets; broker pipe and caller identity; consent
dialog; plan binding and the execute hand-over; elevated settings hardening (S4); check-deps rule change for the
release executor path; undo, purge and recovery through consent.

Others: stdio server and inventory streaming; per-user runner; icon batches; DTO generation; custom Main and launch
markers; bench-launch and the S1 skeleton bench; S1; S2; S3; S4; S7; UI automation harness; VM rig modes (UAC on,
clean Windows start, SendInput test); install.ps1 update; engine output additions the UI alpha asked for.

## 7. Open questions for the user (1-6 answered 2026-11-21)

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
7. **Reuse of the stopgap UI.** Not yet assessed; may become a question once both branches are read.

## 8. Decisions added to DECISIONS.md

2026-11-21 (user): answers to open questions 1-6, one row.

## 9. For the resuming session

Still to read: `docs/M2_DESIGN.json` and `docs/BASELINE_LOCAL_DESIGN.{md,json}` (the schema to match),
`tools/xtask/src/ui_strings.rs` and the `ci` step list, `install/install.ps1`, the two UI branches (`git show
0d9c008:ui/README.md`, `docs/SANDBOX_TEST.md`, `Program.cs`, `ConsentPrompt.cs`, the changed `check_deps.rs`),
`bins/purge-engine/src/cli/exec.rs` (how the rig verbs build `ExecRequest`, to reuse in the broker).

Still to check on this host: whether `Microsoft.WindowsAppSDK.WinUI` and `.Runtime` 2.6.x restore with the .NET SDK
10.0.404 under `C:\Program Files\dotnet` (not on PATH); not attempted yet.
