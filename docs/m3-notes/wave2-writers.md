# M3 waves 1-2: writer notes (coordinator digest of the writers' reports)

Input for the DECISIONS rows and for Fable review M3-R1. One section per package.

## M3-S0 (0ae758d, merged a9aa940)
- Temporary `TEMP_EXEC_DEPENDENTS = ["purge-broker"]` in check_deps.rs, applied in `exec_violations` and
  `default_build_violations`; M3-DEPS replaces it.
- Known: `cargo clippy -p purge-win -p purge-broker --all-targets` fails in purge-exec (unused imports
  `RegBackupBody`, `RegBackupSchema`, `FileTime`, dead `tree_delete_flag` in act_service.rs) under that feature
  set; the workspace clippy (the CI form) passes. Pre-existing feature gating, not M3.

## M3-UI-IMPORT (99f9c20, merged)
- Six rail pages kept: Programs, Uninstall pipeline (old Queue), Leftovers, History & undo, Quarantine vault,
  Settings. Consent state still `Shell/ConsentPrompt.cs`; narrow layout (< 720 px) not built; high contrast
  partial. CliEngineClient + EngineJob moved to Purge.Client.Tests/Cli (ExecAsync throws). Program.cs always
  uses FakeEngineClient until the RPC client lands.
- `xtask ui-strings` NOT run: the reference strings file is not on the laptop. Run where it lives.
- Left for later UI packages: Settings expanders section 10 says are not shown ("Always start as
  administrator", packs, other profiles, running-apps wording); unused EngineHello.BuildNote,
  ProgramsView.ShowEngineNotice; hardcoded rail badges.

## M3-RIG-UAC (c74e90c, merged 77ded10)
- Inbound-Win11-Test, 26100.1742, snapshot `m3-uac-on` (rig-base already had the defaults 5/1/LUA 1).
- Medium -> high dialog: 0/9 (SendInput reports success but is dropped: judge by the dialog's own journal;
  PostMessage/SendMessageTimeout error 5; UIA tree partial, Invoke throws). High control: 4/4 (WM_COMMAND is
  ignored by TaskDialog even from high). TaskDialog buttons are real child Button windows: BM_CLICK is a real
  path, blocked from medium.
- Secure desktop answered from the host: Alt+N `38 31 b1 b8` declines (1223), Alt+Y `38 15 95 b8` approves;
  the prompt focuses No, so bare Enter declines. screenshotpng captures the secure desktop.
- Open by design: hand-run SendInput check (11.3), probe against the real broker dialog (m3-consent),
  standard user credentials (T8, m3-uac).

## M3-WIN-TASKDLG (80128d9, merged 9404a2a)
- `TaskDialogIndirect` resolved via GetProcAddress (a static import would break every unmanifested binary,
  incl. tests); without the v6 manifest `open` returns Unsupported.
- Custom ids >= 100; 9001/9002 reserved Next/Back; Cancel always present and default unless a page sets one;
  primary id once, on the last page; gated button disabled on CREATED/NAVIGATED, enabled by the verification
  box; Approved = primary click + ticked box when gated.
- Not done: "opens on the cursor's monitor" (MonitorFromPoint in TDN_CREATED; for M3-CONSENT). Untested on a
  VM: paging, gating, close from another thread.

## M3-WIN-PIPE (6101ecb, merged 2e6c265)
Choices (DECISIONS candidates):
1. Pipe name: exactly 32 hex digits (128 random bits).
2. SID must match `S-1-<digits>(-<digits>)*` before it goes into SDDL.
3. Access `FILE_GENERIC_READ|FILE_GENERIC_WRITE` (what a .NET InOut client asks); one-instance limit stops a
   second instance.
4. Medium mandatory label, no-write-up + no-read-up (beyond spec).
5. pipe module in the default `read` feature (changes no system state).
6. `PipeError` thiserror enum; new APIs use `Win32Error`.
7. Buffers 64 KiB; read timeout none; write timeout 30 s over the whole write (after it the stream is
   unframed: disconnect).
8. Refused client: disconnect and wait again on the same instance (name never free; client sees busy, UI's
   10 s retry covers it).
9. Image check: case-insensitive exact path, no normalisation, not file identity.
10. Client impersonation token must equal the claimed process's own token (defence in depth).
11. `peer()` refuses if the thread already impersonates (ThreadImpersonating).
12. Failed RevertToSelf aborts the process.
13. Parent exit noticed between bounded reads.
Binding for M3-BROKER-CORE: a client opened without identification/static tracking has no security context
until it writes (error 1368 -> `PipeError::ReadFirst`): read the first request line, then `peer()`, then the
check, answer nothing before it passes (design 3.3 steps 4-6).
Elevated run pending (win-unit p2): token tests adapt at runtime. Do not use `#[ignore = "needs ..."]` for
elevated tests: win-unit.sh skips those even in the elevated pass (also true of existing fs_write tests).
For M3-R1: can a local client set its pipe client pid (FSCTL_PIPE_SET_CLIENT_PROCESS)? squatting (access
denied / busy always an existing name? create-instance right held by the user SID); low-IL/AppContainer kept
out; default owner rights; impersonation window; pid reuse vs creation-time check; overlapped cancel/wait,
partial writes; refusal-loop DoS (accepted by design?).

## M3-WIN-PRIV (d5d0002, merged)
**Elevated path never ran.** Pending on the VM (win-unit elevated):
`cargo test -p purge-win --features write --lib -- --ignored elevated_privilege_scope elevated_reopen_and_set_owner`
and `cargo test -p purge-exec --features test-support --test act_service -- --include-ignored elevated_write_back`.
Relies on: a registry open with REG_OPTION_BACKUP_RESTORE + SeRestorePrivilege grants WRITE_OWNER (from
reading, not a run). If not, the step fails cleanly, the note stays, R8b M1 stays open.
Choices (DECISIONS candidates):
1. Copied token + SetThreadToken instead of ImpersonateSelf (same effect; a failed enable never touches the
   thread). Refuses if not held (1314) or the thread already impersonates (5); process token never adjusted.
2. Two privileged uses, both in purge-win: the M2 one-call use in `CreatedKey::set_security` (E1 SYSTEM-owned
   restores depend on it) and the new `CreatedKey::reopen_and_set_owner` (one caller, act_service.rs
   `set_recorded_security`). Literal only in `restore_luid`. M3-DEPS rule (e) / T10 wording must match.
3. Owner only under the privilege; group/DACL via the plain handle; R8b "SCM-made key, both opens refused"
   unchanged.
4. Failure note text unchanged (does not say the privileged attempt was tried).
5. Raw NtOpenKeyEx relative to the checked handle with an empty name (no name lookup again).
Also touched: crates/purge-exec/tests/act_service.rs (existing converge test returns early when elevated).
For M3-R1: every exit path of `with_restore_privilege` (no thread change before SetThreadToken, drop order
revert-then-close, panic unwind, abort on failed revert); the backup-restore handle never leaves the closure;
one NtSetSecurityObject per closure; owner-only check `sd.info == OWNER_SECURITY_INFORMATION`; link check on
self before the reopen; only one thread sees it; `pub(crate)` + `write` gating; whether public
`thread_impersonates`/`restore_privilege_enabled` should stay in read builds.

## M3-RPC (f4c15b9, merged)
Choices (DECISIONS candidates):
1. One engine error code -32000 with tagged `error.data.kind`; protocol errors (-32700/-32600/-32601/-32602) no data.
2. Invalid UTF-8 / non-JSON / empty line -> -32700, keep reading; oversize line or EOF mid-line closes; batch -> -32600.
3. Envelope: unknown members -32600; id must be u64 (else -32600, id null); absent/null params = {}; array params -32602.
4. Table per method: set + `served` (Stdio|Pipe|Both: one-sided Read methods are -32601 on the other) + `cancellable` + `consent`.
5. No third call set: mask only from `Transport::mask()`, `SetMask` has no public constructor; `StdioCall` (no
   Execute/Propose), `PipeCall` (no UserRun); `CallSet` sealed.
6. Client notifications: only `$/cancel`; others dropped, incl. a request method sent without an id.
7. Broker ids `u-`/`s-`/`p-`/`e-` + 16 lower hex (64 bits); new `ExpiryId` for quarantine.purge; executor
   sessions keep model `SessionId`, ops `OpId`.
8. Wire candidate ids `CandidateRef` `c-<16 hex>`; from model `CandidateId` is fallible.
9. stdio `engine.hello` returns `MediumHello` (EngineHello + elevation_type + shell_matches); broker plain EngineHello.
10. Params: plan.create / leftovers.scan untagged two-form enums, each deny_unknown_fields; `preselected` literally
    true; forced default false; lists non-empty; absent item_ids = all; scan.candidates limit 1-500;
    restore_point off|high_risk|always.
11. Results/notifications accept unknown members (newer server may add fields).
12. Output > 16 MiB: response -> runtime error; notification not written, call errors.
13. Invented result shapes where 6.3 was vague (FingerprintSummary, CandidateRow + ItemKind, PlanCounts,
    AttentionReason, Refusal, Warning{code free text until M3-ENGINE-OUT}, one shared Progress, broker.shutdown {exiting}).
14. Fixture names `<stdio|pipe>.<method>.params|result`, `notification.<name>`, `error.<kind>`; `methods::dtos()` for M3-GEN-DTO.
15. `serve` single-threaded; real cancelling servers use `route`/`write_response`/`write_notification` on their
    threads; checking `cancellable` is the server's job.
16. No MCP/CLI transport in the RPC layer for M3. 17. Deps: schemars, serde_json raw_value.
Binding for M3-STDIO / M3-BROKER-CORE: use `route` (the only path doing the `served` + mask checks); never a
custom lookup over `parse_incoming`. Server must refuse `$/cancel` of non-cancellable requests. Broker must
look ProgramId up only in its own inventory (`HKLM|64|C:/x` parses: key-name part is free text).
For M3-R1: `lookup`/`route`; `call_set!` `_ => method_not_found` arm; sealing + private SetMask;
`Routed::Ignored`; `ID_TYPES` allowlist in the shape walk; ProgramId free text; untagged enums; duplicate keys
refused via raw parse; `Dispatcher::call` returns untyped Value (result types by convention only).

## Elevated unit run on the VM (2026-11-21 20:06, baseline 341f7c3)
Windows-native route (host-built test exes, run through the elevated rig agent on Inbound-Win11-Test
26100.1742, TEMP with D:AI): purge-win `token pipe process` (write,run) 27/27; purge-win `--ignored
elevated_privilege_scope elevated_reopen_and_set_owner` 2/2; purge-exec act_service `--include-ignored
elevated_write_back` 3/3. **R8b M1 fixed on the VM**: the key created without its SYSTEM owner gets `O:SY`
back after the resumed write-back, no note, privilege off before and after. Evidence
E:\purge-build\gate-evidence\m3-win-elev\ (drive script win-elev.ps1 copied there). vm/win-unit.sh stays
Linux-host only.
