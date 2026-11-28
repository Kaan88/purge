# M5: watching the uninstaller (ETW observation)

Plan of 2026-11-28, by the milestone designer (Fable). Branch `plan/m5-m6`. Nothing here is built yet.

The user's decision of 2026-11-28: v1.0 is M4 + M5 + M6 with their UI. Features and UI come first; every VM gate,
eval and corpus test waits until after 1.0, except one VM run of the UI when everything is implemented. This
replaces the DECISIONS row of 2026-11-22 that made M5 release 1.1.

Sources: ENGINE_PLAN §3.1 (process table), §3.6 (step 2 OBSERVE), §5.3 (`Traced`), §6.1 (the ETW reader row),
§11.1 (M5 row), §11.2 ("ETW lost events"); the code at `ui/rust` 348b861. Section 8 lists where this plan departs
from ENGINE_PLAN and why.

## 1. What it means for the user

While an uninstaller that Purge started is running, Purge watches which files and registry keys that uninstaller
creates and removes. The leftover scan that follows uses what was seen:

- **Things the uninstaller made and left behind** (its temporary copy of itself, a log, a key it created) are found
  even when nothing names the program.
- **Folders and keys the uninstaller emptied but did not remove** are found even when their name says nothing
  (`%LOCALAPPDATA%\{GUID}`, `HKCU\Software\<codename>`). This is where uninstallers without a log (NSIS, custom
  ones) gain most.

### When it runs

| Situation | Watched in 1.0? |
|---|---|
| Uninstall run by the broker (machine scope, "as administrator") | Yes |
| Uninstall run at the user's level (medium route) | Yes, by the broker, which is already running for the harvest. Its findings count for less (section 3, T4) |
| App removed outside Purge (external mode, M4) | No: nothing ran under Purge |
| Forced removal (M4) | No: no uninstaller runs |
| Watching an **install** | No. That is M7 ("Install & trace"), after 1.0 |
| MSI products | Only the processes of the uninstaller's own tree. The Windows Installer service does the real work in another process, which is not followed; MSI products are covered by their tables already |

Watching needs administrator rights, so it only ever happens inside the elevated broker. It starts just before the
uninstaller starts and stops when the uninstaller's processes have ended. Nothing is watched at any other time and
no data about other programs is kept (section 3, T2).

### How the user sees it

| Where | What | AutomationId |
|---|---|---|
| Uninstall page, step "Run its uninstaller", detail line | While running: "Watching what the uninstaller changes". After: "Watched: 214 changes by 3 processes" / "Watched with gaps: Windows dropped 37 events" / "Not watched: <reason>" | `TraceStatusText` |
| Leftovers page, details pane, evidence lines | "Created by the uninstaller while it ran" · "The uninstaller removed 14 items from here and left this behind" | existing `DEvidence` |
| Leftovers page, details pane, "found by" | "Watching the uninstaller" | existing `DFoundBy` |
| Leftovers page, bar, only when the watch had gaps or failed | "Watching was incomplete" + "Some changes the uninstaller made may be missing from this list." | `InfoBarHost_n` (one Text "Title Message", as the rig expects) |
| History, cleanup detail | One line: watched / watched with gaps / not watched, with the counts | `HTraceText` |
| Settings, card "Uninstall" | Switch "Watch what the uninstaller changes" with one explaining line ("Purge sees which files and registry keys the uninstaller touches while it runs. Nothing leaves this PC."). On by default (open question 3) | `WatchUninstallerSwitch` |

States of the watch, as the UI shows them: `off` (setting), `watching`, `watched`, `watched_with_gaps`,
`not_watched {reason}`. Reasons are an enum with fixed wording: `setting_off`, `start_refused`, `too_many_sessions`,
`root_not_found` (medium route: the uninstaller's process was never seen), `timed_out`, `failed`. A watch that fails
never stops or delays the uninstall.

No new page, no new dialog. Under the alpha rule (DECISIONS 2026-11-24) the switch appears only in the build where
watching works.

## 2. Design

### 2.1 Where the code lives

```
purge-broker (elevated)
  uninstall.rs ── starts/stops ──► trace.rs  (session thread, Tracer trait, the fake for tests)
                                     │ raw events                       │ TraceDoc
                                     ▼                                  ▼
              purge-win  etw.rs (feature "etw": the only unsafe ETW code)   Fingerprint.trace  ──► fp store
                                     │ RawEvent                                                    │
                                     ▼                                                             ▼
              purge-trace (new crate, pure, forbid(unsafe)): decode, process tree,        purge-scan x_trace.rs
              key-object table, path mapping, reduce to TraceDoc, record/replay           (scanner X-TRACE)
```

- **No `purge-trace.exe`.** The session runs on a thread of the broker. A second elevated executable would need its
  own signing, install path, start checks and an authenticated channel to the broker, and it would still run at
  high integrity. What a separate process would buy, crash containment, is had here by parsing in safe Rust only,
  catching a panic at the callback, and the rule that a failed watch never fails the uninstall.
- **No ferrisetw** (section 5). The Win32 calls go into `purge-win` behind a new feature, like every other Win32
  wrapper of the repo.

### 2.2 The session

- Real-time session named `PurgeTrace-<32 hex digits>` (random per run), started with `StartTraceW`, three
  manifest providers enabled with `EnableTraceEx2`, consumed with `OpenTraceW` + `ProcessTrace` on its own thread.

  | Provider | GUID | Keywords | Events used |
  |---|---|---|---|
  | Microsoft-Windows-Kernel-Process | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | `0x10` (process) | ProcessStart 1, ProcessStop 2 |
  | Microsoft-Windows-Kernel-File | `edd08927-9cc4-4e65-b970-c2560fb5c289` | `0x1C10` (file name, delete path, rename/set-link path, create new file) | NameCreate 10, NameDelete 11, DeletePath 26, RenamePath 27, SetLinkPath 28, CreateNewFile 30 |
  | Microsoft-Windows-Kernel-Registry | `70eb4f03-c1de-4f73-a051-33d13d5413bd` | `0x7301` (create, open, delete key; set, delete value; close key) | CreateKey, OpenKey, DeleteKey, SetValueKey, DeleteValueKey, CloseKey |

  The GUIDs, ids and keyword masks were read from this PC's provider metadata (`wevtutil gp <provider> /ge /gm`,
  which works unelevated). ENGINE_PLAN §6.1 has `0x10|0x40` for Process and `0x1490|0x800` for File: the image
  keyword `0x40` and the plain create keyword `0x80` are dropped, because image loads are not used and every open
  of every file on the machine would be the bulk of the volume for no use (CreateNewFile has its own keyword).
  CloseKey `0x1` is added so the key-object table can forget closed keys.
- Buffers: 64 KB each, 64 to 256 of them (at most 16 MB), flush timer 1 s.
- The providers are system-wide and kernel providers take no process filter, so the consumer filters: an event
  whose process id is not in the tree is dropped in the callback before anything of it is parsed or stored.
- Windows reports dropped events and buffers (`EventsLost`, `RealTimeBuffersLost`, also per buffer in the buffer
  callback). The sum is `lost` in the result. `lost > 0` is "watched with gaps".
- Stop: when the run ends, the broker waits one flush (at most 2 s), stops the session and joins the thread.
  A hard limit stops any session after 60 minutes whatever else happens.
- **Stale sessions.** An ETW session belongs to the system, not to the process: if the broker dies, its session
  stays until the next restart of Windows. So at every broker start, and before every new session, the broker
  lists the sessions and stops each whose name starts with `PurgeTrace-`. Only one session of ours exists at a
  time.
- **No privilege.** Administrators may run such a session without enabling a privilege. check-deps rule 4e (one
  privilege, one place) must still pass unchanged. If the implementer finds a privilege is needed after all, the
  package stops and reports; it does not add one.

### 2.3 The tree

The watched set of processes ("the tree") is kept by `purge-trace` from ProcessStart and ProcessStop events,
keyed by (process id, start time), so a reused process id is another process.

- **Root, broker route:** the process the broker's runner created, given by the runner (id and start time).
- **Root, medium route:** the medium engine creates it, and the broker does not take a medium process's word for
  which one it was. The broker picks it out itself: the first ProcessStart after `uninstall.watch` whose image is
  the executable of the command `prepare` froze for this session, and whose parent chain reaches the pipe client
  (the UI the broker already checked) within three steps. No such process within the session: `root_not_found`.
- **A child joins the tree only if it belongs to the uninstall.** Its parent is in the tree, and its image is
  (a) inside a validated root of the fingerprint or one of its exes, or (b) inside a directory the tree itself
  created (NSIS's `~nsu.tmp\Au_.exe`, Inno's `_iu*.tmp`), or (c) one of a fixed list of Windows helper programs in
  `%SystemRoot%\System32` or `SysWOW64` (`msiexec`, `regsvr32`, `rundll32`, `cmd`, `reg`, `sc`, `schtasks`,
  `taskkill`, `icacls`, `netsh`, `wevtutil`, `powershell`, `conhost`; the list is data in `purge-trace`, reviewed).
  Any other child is a **foreign child**: not in the tree, nor is anything it starts. It is counted in the result.
  Without this rule an uninstaller that opens a survey page in the browser would make the browser's whole profile
  "created by the uninstaller".
- The consumer waits (at most 5 s) for the root before it handles its first event, so no early event is lost.

### 2.4 What is recorded: `TraceDoc` (`purge.trace/1`)

Reduced in `purge-trace`, stored in `Fingerprint.trace` (optional, absent in older fingerprints), written to the
admin-only fp store with the fingerprint.

```
{ "schema": "purge.trace/1", "state": "watched | watched_with_gaps | not_watched", "reason": null,
  "route": "broker | medium", "lost": 0, "processes": 3, "foreign_children": 1, "unparsed": 0, "unresolved": 2,
  "created":  [ {"target": <Target: path or key>, "by": "<image name>"} ],
  "cleared":  [ {"target": <Target: the container>, "removed": 14, "by": "<image name>"} ],
  "omitted":  {"created": 0, "cleared": 0} }
```

- `created`: a file or directory from CreateNewFile, or a key from CreateKey with disposition "created new" and a
  success status. A rename's new name counts as created, its old name as removed.
- `cleared`: the direct parent (directory or key) of something the tree removed (file, directory, key, value),
  with how many direct children were removed. Only the direct parent, never an ancestor further up.
- Targets are in the engine's canonical spelling. `\Device\HarddiskVolumeN\…` is mapped through the drive table
  read at session start (`QueryDosDeviceW`); `\REGISTRY\MACHINE` → `HKLM`, `\REGISTRY\USER\<SID>` → `HKU\<SID>`
  (and `<SID>_Classes`). Anything else (another device, an application hive `\REGISTRY\A\…`, a network path) is
  dropped and counted in `unresolved`.
- Registry delete and set events name the key only by its kernel object. The table from object to name is filled
  from CreateKey and OpenKey events of tree processes and emptied by CloseKey; an object not in the table is
  counted in `unresolved`, never guessed.
- Caps: 20,000 entries per list (the rest counted in `omitted`), strings 32,767 characters, the key-object table
  100,000 entries. An event of an unknown (provider, id, version) is counted in `unparsed` and skipped, like the
  Inno reader's version gate.
- Not recorded: reads, opens, value data, file contents, anything of a process outside the tree.

### 2.5 Evidence and the scanner

Two evidence kinds in `purge-model` (§5.3 table), produced only by the new scanner `X-TRACE` in `purge-scan`:

| Kind | Tier | W | Scope | Verified by |
|---|---|---|---|---|
| `Traced` | A, **capped to B in 1.0** (below) | 10 | Path or Key, as observed | `TraceDoc.created` holds the exact target, and it still exists |
| `TracedCleared` | B | 4 | Path or Key | `TraceDoc.cleared` holds the exact target, it still exists, and it is not a structural container, a known folder, a volume or hive root, or present in the baseline |

- **The 1.0 cap.** ENGINE_PLAN gives `Traced` Tier A with weight 10, which makes an item Safe and so ticked by
  default. Nothing about tracing has been measured, and the measuring is deferred. Until it is done, `X-TRACE`
  lowers every `Traced` to Tier B (one constant, `TRACE_TIER_CAP`, next to the evidence table), so a watched item
  is listed and explained but never ticked for the user on the watch's word alone. This is the same idea as the
  local baseline's trust cap. Lifting it is a recorded decision after the VM measurement (open question 1).
- **Rule T.** Evidence from a medium-route watch has trust `UserWritable`: the process was the user's own, and a
  same-user program could have started that command itself. Rule T then keeps it from attributing machine-scope
  targets at Tier A even after the cap is lifted. A broker-route watch is `AdminOnly`.
- **Gaps.** With `lost > 0` every `Traced` of that session is Tier B whatever the cap says: a lost ProcessStop
  followed by a reused process id could attribute another process's work to the tree.
- `X-TRACE` runs in `Post` scans only. For each surviving target it emits a candidate with the trace evidence and
  then tries the framework's ordinary evidence constructors on the same target (name tokens, harvested token,
  vendor subfolder, time window, references into a root), so a cleared folder that also carries the app's name
  scores as it would for FS-APPDATA. Candidates for the same target from other scanners merge as they do today.
- Everything after the scanner is unchanged: the guard, the deny lists, the blockers for other apps' property,
  the bands, user data never preselected, quarantine and undo. A watched item is a candidate like any other.
- Explanation templates (`purge-policy::explain`): "Created by the uninstaller while it ran" and "The uninstaller
  removed {n} items from here and left this behind". The policy version is raised once for M5; M4 may raise it
  too, so the coordinator merges those two changes one after the other.

### 2.6 RPC (types in `purge-rpc`, tables and schema tests updated)

| Change | Set | Notes |
|---|---|---|
| `RunParams.watch: bool` (default true) | Execute | `uninstall.run` starts the watch itself |
| New `uninstall.watch {session_id}` → `{state, reason?}` | Execute, pipe, no consent | Medium route: the UI calls it after the user confirmed and before `uninstall.run_user`. It only starts a watch, for a session this broker prepared; it is ended by `uninstall.observed` or the 60-minute limit; a second call for a running watch is refused |
| `RunResult.trace`, `ObservedResult.trace`: `TraceSummary {state, reason?, lost, processes, changes, foreign_children}` | | What the pipeline page and History show |
| `uninstall.progress` step detail "watching" | | For `TraceStatusText` |

## 3. Safety invariants

| # | Invariant | Enforced in | Tests |
|---|---|---|---|
| T1 | A watch never changes whether or how the uninstaller runs: every failure is `not_watched`, start has a 500 ms budget, stop a 2 s one | `purge-broker/src/trace.rs`, `uninstall.rs` | Fake tracer that refuses, hangs or panics at each step: the run result is the same as unwatched but for `trace` |
| T2 | Only events of tree processes are parsed or stored; no read, no value data, no content | the callback in `trace.rs`, `purge-trace::reduce` | Recorded stream with 10,000 foreign events: none in the `TraceDoc`; the `TraceDoc` type has no field for data |
| T3 | A foreign child and its descendants are never in the tree | `purge-trace::tree` | Browser case (child image outside roots and helper list writes 500 files): none recorded, `foreign_children` 1; helper case (`cmd /c del`): recorded; process id reuse after stop: not a member |
| T4 | Medium-route evidence is `UserWritable`; the root is found by the broker, not named by the client | `trace.rs`, `x_trace.rs` | Rule T test: machine-scope target with medium-route `Traced` is Tier B with the cap lifted in the test; root search refuses a same-named image whose parent chain misses the client |
| T5 | `Traced` never makes an item Safe or ticked in 1.0; with gaps never | `TRACE_TIER_CAP`, `x_trace.rs`, policy tests | For every fixture, no candidate whose only Tier A source is trace evidence is Safe or preselected; a test that fails when the constant changes without the decision id next to it |
| T6 | Trace evidence only on the exact target seen; `cleared` only the direct parent; never a structural container, known folder, root or baseline key | `x_trace.rs` with `purge-guard` containers | Uninstaller deletes a shortcut on the Desktop: no candidate for the Desktop; deletes a value under `…\CurrentVersion\Run`: no candidate for `Run` |
| T7 | Hostile event content cannot break the broker: all decoding is bounds-checked safe Rust, a panic is caught at the callback, strings are capped and used only as paths through guard canonicalisation | `purge-trace` (`#![forbid(unsafe_code)]`), `trace.rs` | Truncated, oversized and random payloads for every (provider, id, version): never a panic, counted `unparsed`; names with NUL, `..`, device prefixes, 32k length |
| T8 | Sessions do not pile up: one at a time, stale ones stopped at start, hard 60-minute stop, stop on every exit path of the broker that still runs code | `trace.rs`, `purge-broker/src/start.rs`, `lifetime.rs` | Fake ETW API: sweep stops exactly the `PurgeTrace-` names; second start refused; drop stops |
| T9 | Losses are counted and shown, never hidden | `purge-win::etw` stats, `TraceSummary` | Fake stats with losses: state `watched_with_gaps`, the bar's text, tier lowered |
| T10 | Only the broker can trace: `purge-win/etw` is asked for by `purge-broker` alone; `purge-trace` is in no tree but the broker's; the broker links no new outside crate | `xtask check-deps` (new rule next to 4f; `BROKER_OUTSIDE` unchanged) | check-deps' own unit tests with a manifest that breaks each |
| T11 | No privilege is enabled for tracing | check-deps rule 4e, unchanged | existing |

What the unit tests cannot show, and the one VM run must: that the session starts on a clean Windows 11 at all,
that the hand-written event layouts match what the kernel sends, and that a stale session is really stopped.
`purge-win::etw` gets `#[ignore]`d live tests for these (they need elevation; never run on the dev PC).

## 4. Packages

Each is one agent session, in its own worktree `E:\purge-ui-wt\<name>` on a branch from `ui/rust`. Fable reviews
M5-CONTRACT (evidence table), M5-ETW, M5-PARSE and M5-BROKER before merge: they are the elevated or
band-deciding parts.

| Order | Package | Crates and files | Depends on |
|---|---|---|---|
| 1 | **M5-CONTRACT** | `purge-model` (`trace.rs`: `TraceDoc`, `TraceSummary`; `evidence.rs`: `Traced`, `TracedCleared`, `TRACE_TIER_CAP`; `fingerprint.rs`: `trace`), `purge-policy` (`explain.rs`, version), `purge-rpc` (`methods.rs`, `table.rs`: 2.6), `tools/xtask` (`check_deps.rs`: T10; `gen_dto`), `Cargo.toml` (member `crates/purge-trace` as an empty crate) | — |
| 2 | **M5-ETW** | `crates/purge-win` (`Cargo.toml` feature `etw`, `src/etw.rs`) | 1 |
| 2 | **M5-PARSE** | `crates/purge-trace` (`decode.rs`, `tree.rs`, `keys.rs`, `paths.rs`, `reduce.rs`, `record.rs`, `helpers.rs`, tests and fixtures) | 1 |
| 2 | **M5-SCAN** | `crates/purge-scan` (`x_trace.rs`, `catalog.rs`, the shared `framework` helper), `tools/xtask` (`scanner_coverage.rs`) | 1 |
| 3 | **M5-BROKER** | `bins/purge-broker` (`trace.rs`, `uninstall.rs`, `start.rs`, `serve.rs`, `history.rs`, `testkit.rs`, `examples/etw_record.rs`), `Cargo.toml` (deps) | 2 (all three) |
| 3 | **M5-UI** | `crates/purge-ui-model` (`pipeline/`, `leftovers/text.rs`, `history/`), `crates/purge-client` (`sample.rs`, the `uninstall.watch` call), `bins/purge-ui` (`screens/pipeline.rs`, `leftovers.rs`, `history.rs`, `settings.rs`, `prefs.rs`, `script_steps.rs`, `sample_broker.rs`) | 1; runs beside M5-BROKER on the sample broker |

**M5-CONTRACT.** The types of 2.4 to 2.6 with serde and schema tests in the repo's style (round trips, unknown
fields refused, an old fingerprint without `trace` still reads). The §5.3 row tests in `evidence.rs` (the test
that says `"Traced"` does not deserialize is replaced). The check-deps rule T10 with its unit tests. No behaviour.

**M5-ETW.** Contract:

```
pub struct Provider { pub guid: Guid, pub keywords: u64, pub level: u8 }
pub struct Config { pub buffer_kb: u32, pub min_buffers: u32, pub max_buffers: u32, pub flush_secs: u32 }
pub struct RawEvent<'a> { pub provider: Guid, pub id: u16, pub version: u8, pub opcode: u8, pub pid: u32,
                          pub tid: u32, pub time: FileTime, pub pointer_size: u8, pub payload: &'a [u8] }
pub struct Stats { pub events_lost: u64, pub buffers_lost: u64 }
pub fn start(name: &str, providers: &[Provider], config: &Config) -> Result<Session, EtwError>;
impl Session { pub fn stopper(&self) -> Stopper;                      // Send + Clone; stops from any thread
               pub fn run(self, sink: &mut dyn FnMut(&RawEvent<'_>)) -> Result<Stats, EtwError>; } // blocks
pub fn sessions_named(prefix: &str) -> Result<Vec<String>, EtwError>;
pub fn stop_named(name: &str) -> Result<(), EtwError>;
pub fn device_map() -> Vec<(String, String)>;                         // \Device\HarddiskVolume3 -> C:
```

`windows-sys` gains the feature `Win32_System_Diagnostics_Etw` for `purge-win`; everything in `etw.rs` is behind
`#[cfg(feature = "etw")]`, `Drop` stops the session, the callback catches a panic and stops. Tests: the
properties buffer and the name rules as plain unit tests; the live tests `#[ignore]`d with the reason.

**M5-PARSE.** `decode(&RawEvent) -> Option<Event>` for the events of 2.2, each (provider, id, version) a
hand-written layout with a version gate. The layouts come from the provider metadata of this PC
(`wevtutil gp <provider> /ge /gm /f:xml`, unelevated and read-only; the implementer writes the field lists into
`crates/purge-trace/src/layouts.rs` with the Windows build they were read on). `Tree`, `KeyTable`, `reduce(...) ->
TraceDoc` as in 2.3 and 2.4, all fed through one `Reducer::push(&RawEvent)`. `record.rs`: a line-per-event JSON
form of `RawEvent` (`purge.etw-rec/1`, payload in hex) with a reader and a writer, so a stream can be saved in
the VM later and replayed in a test. Tests: fixtures built by a test helper from the layouts (there is no real
capture before the VM run); the cases of T2, T3 and T7; a whole made-up NSIS uninstall (temporary copy, deletes,
a key left empty) reduced to a golden `TraceDoc`.

**M5-SCAN.** `X-TRACE` as in 2.5, appended to the catalog. The helper that tries the ordinary constructors on a
given target goes into `framework` as `evaluate_location(ctx, app, target) -> CandidateBuilder` (M6-PROBE uses the
same one; whichever lands first adds it). `scanner-coverage`: X-TRACE reads where the trace points, so it gets an
explicit "directed" entry instead of fixed roots; the package says in its handback how it did that. Tests over
`purge-source` fixtures: T5, T6, the merge with FS-APPDATA, gone targets dropped, External and Forced scans emit
nothing.

**M5-BROKER.** A `Tracer` trait (`start(root_hint) -> Running`, `finish() -> TraceDoc`) with the live one (the
session thread, `Reducer`) and a fake that replays a `purge.etw-rec/1` file; `Machine::run_uninstall` and the
`uninstall.watch` / `uninstall.observed` pair use it; the runner reports the root (a `ProcessHost` wrapper around
`LiveHost`, no change to the runner's behaviour); the sweep at start; the `TraceDoc` into the fingerprint before
it is stored; `TraceSummary` into the results and into the session's history record. `examples/etw_record.rs`
writes a live stream to a file (for the VM run; not shipped). Tests: T1, T4, T8, T9 through the flow tests with
the fake tracer; no test starts a real session.

**M5-UI.** The rows of section 1. The pipeline model learns the watch states and calls `uninstall.watch` on the
medium route when the switch is on; the sample engine and sample broker get a watched NSIS-style sample and a
"gaps" one; the script walk gets steps that check `TraceStatusText`, the evidence line and the bar. Wording is
Purge's own (`xtask ui-strings`).

## 5. New crates

**None from outside.** One new workspace crate, `purge-trace`, and one more feature of a crate already linked:

| What | Licence | Why |
|---|---|---|
| `windows-sys` feature `Win32_System_Diagnostics_Etw` (in `purge-win`, feature `etw`) | MIT OR Apache-2.0 (already in the tree, 0.61) | The ETW calls. Nothing new is linked into the elevated broker; `BROKER_OUTSIDE` stays as it is |

**ferrisetw, which ENGINE_PLAN names, is not used.** Checked on crates.io today: 1.2.0 (MIT OR Apache-2.0) is its
newest release, from June 2024. It depends on `windows` 0.57 (the workspace is on 0.62, so the broker would link
a second copy of the Windows bindings), `rand` 0.8, `num`, `num-derive`, `num-traits`, `bitflags` 1, `memoffset`,
`once_cell`, `widestring`, `zerocopy` 0.7 and `log`. check-deps rule 6 lists every outside crate of the elevated
binary by name; this would add about a dozen (more with their own dependencies) for four Win32 calls and a parser
of about twenty fixed layouts. The cost of doing without it is the hand-written layouts, which are gated by
version and counted when unknown.

## 6. Deferred until after 1.0

- Every measurement: recall uplift on NSIS and custom uninstallers, the danger and precision gates with trace
  evidence, the cost of watching on the uninstall's run time, losses under load.
- Lifting `TRACE_TIER_CAP` (a decision after those numbers).
- Real captured event streams as fixtures (recorded in the VM with `etw_record`).
- Following the Windows Installer service for MSI products.
- USN bracketing (ENGINE_PLAN §6.1 puts it in the M5 row; USN as a whole is M7).
- Watching installs (M7).
- Evidence from value writes (recorded as a count only).

The one VM run of the UI after everything is implemented should include one watched uninstall of an NSIS app on
each route, the live tests of `purge-win::etw`, and a look at `logman query -ets` afterwards for a leftover
session.

## 7. Conventions for the agents

- Rust builds and tests run on the laptop: `tools/laptop/lt.sh <worktree> <cargo args>` (read the script's head).
  For example `tools/laptop/lt.sh E:/purge-ui-wt/m5-parse test --release -p purge-trace`. `cargo fmt` may run
  locally.
- The app runs on the PC: `tools/laptop/lt.sh <worktree> --fetch Purge.exe purge-engine.exe purge-broker.exe`,
  then `powershell -NoProfile -File tools\desk\run-hidden.ps1 -Exe E:\purge-target\lt\<name>\Purge.exe -Args
  '--sample --script'`. UI tests only ever on the hidden desktop.
- Worktrees in `E:\purge-ui-wt\<name>`, one branch each from `ui/rust`. Never push, never touch `main`, `baseline`
  or the main checkout; the coordinator merges.
- No VM, no VBoxManage, no outside models. Nothing elevated and nothing destructive on the dev PC: Claude Code
  runs unelevated there, and no test may start an ETW session, run an uninstaller or write outside its temp
  directory. Live ETW tests are `#[ignore]`d.
- Gates before handing back: `cargo fmt --all -- --check`, `cargo clippy -p <your crates> --all-targets -- -D
  warnings`, `cargo test -p <your crates>`, `cargo xtask check-deps`, and for UI packages the hidden-desktop
  scripted walk.
- No new third-party crate without the user's OK (this plan needs none). The repo's conventions: doc comments
  that say why, no `unwrap` outside tests, errors as `thiserror` types. Read `AGENTS.md` before any UI work.
- Small commits with clear messages, ending with the attribution lines given.
- At most three agents run at once, over M4, M5 and M6 together.

### Shared files (with M4 and M6)

`purge-rpc` (`methods.rs`, `table.rs`), `purge-model/src/evidence.rs`, `purge-policy` (version, `explain.rs`),
`purge-scan` (`catalog.rs`, `framework.rs`), `bins/purge-broker/src/uninstall.rs` and `serve.rs`,
`tools/xtask/src/check_deps.rs` and `scanner_coverage.rs`, and in the UI `screens/leftovers.rs`,
`screens/settings.rs`, `script_steps.rs`. Therefore: M5-CONTRACT and M6-CONTRACT are merged one after the other
before either milestone fans out; M5-UI and M6-UI do not run at the same time; whoever merges second rebases.
`docs/M4_PLAN.md` (branch `plan/m4`) did not exist when this was written; the coordinator checks its package list
against the list above (M4's scanners also append to `catalog.rs`, and its forced and external modes also touch
`uninstall.rs` and the rpc tables).

## 8. Where this plan departs from ENGINE_PLAN

| ENGINE_PLAN | This plan | Why |
|---|---|---|
| §3.1, §3.2: a separate `purge-trace.exe` | A thread in the broker, a pure crate `purge-trace`, Win32 in `purge-win` | 2.1 |
| §3.5: ferrisetw | `windows-sys` | section 5 |
| §5.3: `Traced` = created by the tree, Tier A, W 10 | Kept, but capped to Tier B in 1.0; plus `TracedCleared` (B, 4) | Creation is what an *install* trace sees. An uninstaller mostly removes, so the uplift the M5 row asks for comes from what it emptied and left. And nothing is measured yet |
| §6.1: Process `0x10\|0x40`, File `0x1490\|0x800` | Process `0x10`, File `0x1C10`, Registry `0x7301` | 2.2 |
| §6.1: USN bracketing in M5 | Deferred with the rest of USN | No use without the install side |
| §6.1: "broker processes counted within the window" | The tree rule of 2.3 (foreign children left out) | The browser case |
| §11.1: exit = recall uplift on NSIS, `EventsLost` reported | Losses are reported in 1.0; the uplift is measured after it | The user's decision of 2026-11-28 |

## 9. Open questions for the user

1. **May a watched item be ticked by default?** Recommendation: not in 1.0. Items found by watching are listed and
   explained but start unticked (`TRACE_TIER_CAP`), until the VM measurement after 1.0 shows the danger side is
   clean. The other choice follows ENGINE_PLAN (Tier A at once) and preselects on unmeasured evidence.
2. **No `purge-trace.exe` and no ferrisetw.** Recommendation: as planned here (a thread in the broker, no new
   outside crate). The other choice adds a second elevated executable and about a dozen crates to the elevated
   side.
3. **On by default?** Recommendation: yes, with the switch in Settings. It runs only while an uninstaller runs,
   keeps nothing about other programs and sends nothing anywhere.
