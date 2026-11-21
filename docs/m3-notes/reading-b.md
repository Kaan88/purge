# Reading B — stopgap UI, rig exec path, purge-rpc today

## 1. Stopgap UI at 0d9c008 (branch `origin/worktree-agent-a7c285be2b9791f54`)

What it is
- Commit `0d9c008` (2026-11-16), "Sandbox dev build: engine lifetime, scan progress with elapsed time, exit codes 12 and 13".
- Built on `973a791` (the UI shell) plus the M2 merge; it is the branch the Sandboxie guide uses.
- `ui/README.md` calls it a shell skeleton on sample data; `docs/SANDBOX_TEST.md` is the end-to-end Sandboxie trial guide.
- The main path is wired to the real CLI engine; Home, Queue, History, Footprint, Assistant, Startup still show SAMPLE data (`docs/SANDBOX_TEST.md` "Known limits").

Tech stack (`ui/Purge.App/Purge.App.csproj`, `ui/README.md` "Stack")
- C# / .NET 10, TFM `net10.0-windows10.0.19041.0`, x64, unpackaged (`WindowsPackageType=None`), self-contained, Native AOT on publish.
- WinUI 3 via component packages only: `Microsoft.WindowsAppSDK.WinUI` 2.6.5 + `Microsoft.WindowsAppSDK.Runtime` 2.6.5 (not the metapackage).
- Custom `Main` (`DISABLE_XAML_GENERATED_MAIN`); runs `asInvoker`; elevation is meant to go through `purge-engine --broker` later.
- `ui/Purge.Client` holds `IEngineClient`, the CLI client and the fake; models are hand-written until M3 schema generation.
- `ui/Purge.Client.Tests` is a plain test project with sample JSON fixtures.

Screens / shell (`ui/Purge.App/MainWindow.xaml.cs`)
- Custom title bar, Mica, left rail of plain Buttons (`MainWindow.xaml.cs:22`, rail + navigation at `:134`).
- S1 Programs (built for the first frame), S2 Uninstall queue, S3 Leftover review, S4 History & undo, S5 Settings, S6 Assistant.
- Extra board pages: Home, Quarantine vault, Footprint, Startup placeholder, command palette (Ctrl+K/Ctrl+F), inline Ask.
- S3 review is opened from S1 via `MainWindow.OpenReview()` (`MainWindow.xaml.cs:76`).
- `--page`, `--query`, `--theme`, `--sample`, `--bench-exit` development switches; launch markers in `Shell/LaunchMarkers.cs` (`Program.cs:71-123`).

How it talks to the engine (`ui/Purge.Client/Cli/CliEngineClient.cs`)
- One child process per verb, no long-lived pipe: `new ProcessStartInfo(EnginePath)` with `UseShellExecute=false`, redirected stdout/stderr/stdin, stdin closed immediately (`:206-218`).
- Arguments passed as `ArgumentList`; engine found next to `Purge.exe` or via `PURGE_ENGINE_EXE` (`:23`, `:33-36`).
- `--version` for hello (`:68`); `inventory --json` (`:79`); `harvest <id> -o fp.json` (`:113`); `uninstall <id> --quiet --fp fp.json -o run.json` (`:117`); `scan --fp fp.json --mode post|forced -o plan.json` (`:123`).
- Exec: writes `select-<n>.json` (JSON array of candidate ids, `:297`) and runs `exec --plan <plan> --confirm <hash> --select <select> --restore-point off -o report.json` (`:129-142`).
- Undo: `undo --session <id>` (`:147`); recovery: `journal recover` (`:156`), `journal resume|rollback` (`:164`).
- JSON is read from stdout or from files (plan sidecar `<plan>.scan.json`, report, session index); all reads use hand-written `EngineDocs` over `JsonDocument` to stay AOT-safe.
- Exit codes are mapped to `EngineException`; `Expect(run, ...)` accepts e.g. 0/10/12/11.
- Stderr lines stream to `IProgress<EngineProgress>` as human progress text (`:206-260`).
- Every engine process is placed in a kill-on-close job object (`Cli/EngineJob.cs`) so no engine outlives the window; `MainWindow.Closed` disposes the client.
- Cancellation kills the whole process tree; after exit, pipes are drained for at most 10 s (`DrainTimeout`) because an uninstaller child can hold them.
- Scan/exec working files go to `%LOCALAPPDATA%\PurgeSandboxDevWork`; the sandbox store root is `PURGE_SANDBOX_DEV_ROOT` or `%LOCALAPPDATA%\PurgeSandboxDev` (`:48-57`).

Consent prompt (`ui/Purge.App/Shell/ConsentPrompt.cs`)
- Not a WinUI dialog: a raw Win32 `TaskDialogIndirect` on an STA thread (`:28-40`, `:133`), owner = window HWND, Common Controls v6 manifest dependency.
- Layout is explicitly a preview: in M3 the elevated broker must show it at high integrity (`:22-26`, footer at `:129`).
- Three variants via `ConsentAction` (`:12`): Quarantine (default), Delete for good, Restore.
- Inputs: `ConsentItem(Path, Kind, Band, SizeText, SizeBytes, IsUserData)` and `ConsentSummary(AppName, Items, RestorableUntil, Action)` (`:9-15`).
- Quarantine text: items come from Purge's own scan, everything is restorable from History & undo until a date (`:54-60`).
- Counts by type: files/folders with total size, registry keys/values, scheduled tasks/services; Safe vs "you ticked yourself" (`:71-88`).
- "Needs your attention" section lists user-data items with size (`:82-88`); expanded pane lists every item, ⚠ for user data (`:90-93`).
- Primary button is a custom id (`100`) with a count-bearing label; Cancel is the default and the only common button (`:95-115`).
- If user-data items exist, a verification checkbox gates the primary button through a TaskDialog callback (`:118-126`, `:144-157`).
- Returns `true` only when the custom primary button was pressed; Cancel/close returns false.
- Content is UI-side strings, not engine strings; no engine-supplied plan digest is shown in this preview.

`check_deps` change needed
- The branch adds rule 5: purge-exec's `test-support` may be enabled only by purge-engine's `sandbox-dev` feature.
- Added `SANDBOX_DEV` const (`tools/xtask/src/check_deps.rs:199`), `test_support_paths` (`:205`), `test_support_violations` (`:239`), `engine_manifest` via `cargo metadata` (`:322`), wired in `run` (`:402`), plus tests (`:548`).
- It refuses any other feature (including `rig-exec`/default) or normal dependency that turns on `purge-exec/test-support`, and requires `cargo tree -p purge-engine --features sandbox-dev` to actually include it.
- No UI code is checked by this rule; it is purely a Cargo feature-graph guard.

Reuse assessment
- Reusable as-is or near as-is:
  - stack decisions and `.csproj` shape (WinUI component packages, TFM, AOT, unpackaged, custom Main);
  - startup ordering: hello/list before XAML, fallback notice on engine failure (`Program.cs:23-60`);
  - `ConfirmHash` (`ui/Purge.Client/Cli/ConfirmHash.cs`): byte-for-byte the Rust selection/confirm recipe, must be shared with the broker;
  - `EngineDocs` schema readers and model shapes (they mirror `purge.scan/0`, `purge.exec/1`, `purge.undo/1`, `purge.sessions/1`);
  - process lifecycle lessons: job object, kill-tree on cancel, drain timeout, stderr-as-progress;
  - `ConsentPrompt` layout, strings, TaskDialog structs and verification gating — port into the broker process;
  - shell/navigation/styles/views and launch markers as the visual/measurement baseline.
- Throwaway or to replace:
  - one-process-per-verb CLI transport as the final UI link; M3 needs `--stdio` NDJSON and a broker pipe;
  - passing plans/selection through temp files and `%LOCALAPPDATA%` work dirs;
  - sandbox-dev-specific roots, `SANDBOX_DEV` title/notice and "Force remove" wording;
  - `FakeEngineClient`, sample pages and their SAMPLE banners as product behaviour;
  - the consent prompt's "preview" title/footer and its medium-integrity execution context;
  - `--select` as a separate file: the broker should bind plan + selection + confirm in one request.

Other UI branches
- `origin/ui-shell` = `origin/claude/ui-shell-7a9c31` = `973a791` (2026-11-13), "UI shell: WinUI 3 app with board decisions on sample data". Original skeleton: all screens on sample data, `ConsentPrompt` preview, no engine wiring.
- `origin/ui-alpha` = `5d7df3c` (2026-11-18), "UI alpha: merge m1b c388dd1". Same shell after merging M1b; adds `Shell/Alpha.cs` (disables every mutating button with "Coming in M3"), `CliEngineClient`, `EngineDocs`, `ConfirmHash`, `PlanExport`, scan/review wiring and more tests. It is the scan-and-review-only sibling of 0d9c008; 0d9c008 adds engine lifetime/progress/exit-12 handling and the Sandboxie guide.
- No separate "stopgap"/"shell" branch beyond these; `origin/worktree-agent-a7c285be2b9791f54` is the 0d9c008 branch.

## 2. Rig CLI exec path (`bins/purge-engine/src/cli/exec.rs`)

Entry and dispatch
- `run_live(verb, env)` builds the live host: store roots, elevation flag, package/service/task/firewall backends, Restart Manager, pending renames, restore points, expiry clock offset (`exec.rs:170-195`).
- `run<R: RestorePointBackend + Clone>(verb, env, host)` checks fault env, refuses non-elevated mutating verbs, then dispatches (`:241-276`).
- `needs_elevation` covers `Exec`, `Undo`, `JournalResume`, `JournalRollback`, `JournalRetryHeld`, `QuarantinePurge` (`:228-238`).
- A normal build never reaches here: `cli.rs:288-303` returns `Exit::NeedsConsent` (5) for every executor verb; only `rig-exec` calls `exec::run_live` (`cli.rs:306-309`).

`plan from-targets` (builds the plan the rig then executes)
- `FromTargetsArgs { targets: PathBuf, out: PathBuf }` (`args.rs:205-210`).
- Reads `purge.rig.targets/0`, converts to `Vec<Candidate>` via `rig_candidates` (`exec.rs:575-651`).
- Builds a `ScanDoc { schema, app, tool, mode: ScanMode::Post, policy_version, plan_hash, items, absorbed }` (`:672-681`).
- Hash: `purge_plan::hash::plan_hash(&items, POLICY_VERSION, mode)` (`:678`).
- Plan: `purge_plan::emit::to_plan0(RIG_APP, mode, &scan.items)` (`:682`); writes the plan and the `<plan>.scan.json` sidecar (`:688-693`).

`exec` (the request the broker will reuse)
- Args: `ExecArgs { plan, confirm, select: Option<PathBuf>, allow_irreversible, restore_point, fp: Option<PathBuf>, out: Option<PathBuf> }` (`args.rs:215-231`).
- Reads the plan from disk (`exec.rs:705-711`) and its sidecar (`:712-719`).
- Sidecar binding: rebuilds `to_plan0(&scan.app, scan.mode, &scan.items)` and requires exact equality with the plan the user saw; otherwise `Exit::PlanRefused` (`:720-728`).
- Selection: no `--select` → `Selection::Preselected`; else `read_ids` reads a JSON array or `{"ids":[...]}` into `Vec<CandidateId>` (`:729-735`, `:447-464`).
- Owners: unique `ProgramId`s of the scan items (`:736-742`).
- Optional `--fp`: `app_facts` checks the fingerprint belongs to an owner, takes its install roots, and computes M1b gone lists from a fresh inventory (`:743-749`, `:856-891`).
- Builds `ExecRequest { scan, confirm, selection, allow_irreversible, settings }` (`:750-768`).
  - `ExecSettings { restore_point, user_sid, long_names_resolved: false, program_roots, gone, ..default }` (`:755-767`).
  - `user_sid` from `purge_win::sid::current_user_sid()`.
- Binding/refusal before touching the store: `purge_exec::plan_in::bind(&request)` (`:770-778`); any `PlanRefusal` → `Exit::PlanRefused` (6), nothing done.
- Fingerprint/object binding: `unbound_objects(&bound, fp)` refuses selected service/task/firewall ops whose owner or scan-time digest the fingerprint does not vouch for (`:779-792`, `:899-933`).
- Store and preconditions: `roots_of`, `check_nothing_pending`, `deny_list` (`:793-803`).
- Execution: `ExecEnv::new(&roots, &deny, packages, lockers, pending_renames)`, attach object backends and a progress closure, then `purge_exec::execute::execute(request, exec_env, restore_points)` (`:804-829`).
- Result: `exec_recorded` combines session-closed/report/index status; report printed or written as `purge.exec/1`; exit precedence via `worse` (`:837-850`, `:937-959`).

`ExecRequest` and binding (`crates/purge-exec/src/plan_in.rs`)
- `pub enum Selection { Preselected, Ids(Vec<CandidateId>) }` (`plan_in.rs:66-71`).
- `pub struct ExecSettings { restore_point, user_sid, long_names_resolved, key_limit, program_roots, gone }` (`:75-93`).
- `pub struct ExecRequest { scan: ScanDoc, confirm: String, selection: Selection, allow_irreversible: bool, settings: ExecSettings }` (`:215-226`).
- `pub fn bind(request: &ExecRequest) -> Result<BoundPlan, PlanRefusal>` (`:432`).
- Checks, in order (`:8-28`):
  1. `scan.plan_hash` is 64 lower-case hex and equals `purge_plan::hash::plan_hash(items, policy_version, mode)` (`:673-682`).
  2. ids unique over top-level + absorbed items.
  3. absorbed children nest in their parent.
  4. selection: `Preselected` = Safe + preselected; `Ids` may add Likely/Weak, drops empty/duplicate ids, refuses unknown/absorbed/undecided/Blocked/hard-blocked/report-only/unresolvable/protected-descendant items; empty selection refused.
  5. nesting order: inner before outer.
  6. confirmation: `request.confirm == confirm_hash(plan_hash, selection_hash(selected ids))`.
- `selection_hash(ids)` (`:413`) = SHA-256 of de-duplicated ids sorted ordinally, joined with `\n`, UTF-8.
- `confirm_hash(plan_hash, selection_hash)` (`:426-427`) = SHA-256 of the two lower-case hex strings concatenated.
- Fixed vector and exact recipe in the module docs (`:30-45`); the C# `ConfirmHash` matches it.
- `BoundPlan` exposes `plan_hash()`, `selection_hash()`, `items()`, `candidate(item)` (`:348-390`).

Other executor verbs (same host, for broker reference)
- `undo`: `UndoArgs { session, items, confirm: Option<plan_hash>, out }` (`args.rs:235-244`); `UndoRequest`/`UndoSelection` (`exec.rs:1006-1040`); optional `--confirm` must equal the session's plan hash (`:1018-1035`).
- `journal recover|resume|rollback|show|retry-held`, `quarantine expiring|purge` dispatch at `exec.rs:259-275`.
- `quarantine purge` builds `PurgeConsent::naming(ids)` and per-id `confirm_user_data`, naming backup files too (`:1745-1816`).

Design consequences for the broker
- There is no in-memory API today: `exec` is plan-file + sidecar + selection file + confirm string.
- The confirm string is the only consent token a rig build checks; the real consent dialog does not exist in the engine, only the UI preview.
- The broker must preserve all three bindings: plan↔sidecar, selection↔ids, confirm↔plan+selection.
- The fingerprint binding for service/task/firewall ops is deliberately incomplete ("the fuller binding comes with the M3 broker", `exec.rs:893-898`).

## 3. `crates/purge-rpc` today

Files
- `crates/purge-rpc/Cargo.toml` — description "NDJSON JSON-RPC 2.0 protocol and capability sets"; deps only `purge-model`, `serde`, `serde_json`.
- `crates/purge-rpc/src/lib.rs` — 133 lines, the only source file (plus its unit test).

Types and messages (all in `src/lib.rs`)
- `pub const ENGINE_HELLO: &str = "engine.hello"` (`:15`) — the only method name.
- `pub struct EngineHello` (`:19-40`): `version: String`, `elevated: bool`, `user_sid: String`, `shell_sid: Option<String>` (`#[serde(default)]`), `edition: String`, `build: u32`, `ubr: u32`, `policy_version: String`, `#[serde(flatten)] baseline: BaselineStatus`.
- `pub struct BaselineStatus` (`:44-56`): `baseline_available: bool`, `baseline_trust: BaselineTrust`, `baseline_view: Option<BaselineViewRef>`, `baseline_build: BaselineBuild`.
- `pub enum BaselineBuild` (`:62-89`), internally tagged `state`, snake_case variants: `None { reason }`, `Checking`, `Building { parts: Vec<String>, scan_waiting: bool }`, `Done { rescan: bool }`, `Failed { reason }`.
- Re-exported model types used: `purge_model::{BaselineTrust, BaselineViewRef}` (`:11`).
- That is all: no JSON-RPC request/response/error envelope, no notification type, no id type, no method table beyond `ENGINE_HELLO`, no capability enum (`Read`/`Propose`/`Execute`), no NDJSON codec, no transport type.
- The module doc (`:1-9`) states the intended responsibility and that framing/table/capabilities are M3 work; only `EngineHello` exists before M3.

How the binary handles `--stdio` and `--broker` today
- Both are recognised CLI words: `Command::Stdio` / `Command::Broker` (`bins/purge-engine/src/cli/args.rs:87-90`), parsed from `--stdio` / `--broker` (`:483-484`).
- Their help text promises `--stdio` = serve the UI over stdin/stdout (medium integrity); `--broker --pipe <name> --parent <pid> --parent-ctime <filetime>` = elevated broker for the UI (`args.rs:23-25`).
- Both are marked milestone M3 (`args.rs:180`) and are `is_rig_tool() == false` (`:185-188`).
- Parsing returns `Invocation::NotImplemented(cmd, rest)` for `Stdio`, `Broker` and `KbLint` (`args.rs:450-451`).
- `run_inner` prints `purge-engine <cmd>: not implemented yet (milestone M3)` to stderr and returns `Exit::NotImplemented` (`cli.rs:386-394`).
- `Exit::NotImplemented` is exit code 1 (`cli.rs:119`, meaning at `:138`).
- No pipe, parent-process check, parent creation-time check, token, or NDJSON loop exists yet; `--broker`'s `--pipe/--parent/--parent-ctime` are accepted only as trailing text after the not-implemented dispatch.
