# Rust UI: the port plan (Purge.exe on mdshared-ui)

Decided 2026-11-25 (DECISIONS): the approved mockup (`mockup/rust-ui` at `1225d9a`, worktree
`E:\purge-mockup-wt\ui-rs\mockup`) becomes the real window, 1:1 in look. The Rust UI is `Purge.exe`
from the first release, with WinUI dropped from the installer. Releases are frequent GitHub
pre-releases (`0.2.0-alpha.N`). Background: docs/UI_RUST_ASSESSMENT.md (mapping, gaps, risks).

## What the user asked for

- **One look from D1 (refined) and D2 (flow) combined.** D0, D1 and D2 differ mainly in page
  transition, so:
- **Page transition is its own setting**, with more transitions than the mockup had. For example:
  none, fade, slide (D1), the flow transition (D2), slide-up, scale, crossfade with depth. "None" and
  Windows' "Show animations" off both mean no motion.
- **D3 (bold) is a theme choice** next to the combined look.
- **Preset colour themes**, usable in both looks, each in light and dark: accent and surface presets
  (e.g. default blue, teal, violet, amber, rose, graphite) plus "follow the Windows accent".
  Theme mode is system, light or dark. High contrast overrides all of it with the system colours.
- **Every feature in the current build** (the WinUI app in `ui/`). Never-tested features (the AI
  assistant) may be left out. Anything not ported yet shows as "not available yet", never as a
  silent no-op.

## Layout

| Crate | Package | What |
|---|---|---|
| `bins/purge-ui` (bin `Purge` → `Purge.exe`) | UI-SHELL, UI-PAGES | The window: host loop, a11y tree, rail, pages, looks, themes, transitions, settings |
| `crates/purge-client` | UI-CLIENT | Engine over stdio, broker over its pipe, sample engine from fixtures. No toolkit |
| `crates/purge-ui-model` | UI-MODEL-A, UI-MODEL-B | View models: plain state machines, no I/O, no toolkit, `cargo test`able |

The toolkit is a workspace dependency (`mdshared-ui` with `host`, `a11y`; `mdshared-app`) pinned to
main `294d330`. No other new third-party crates without the coordinator's OK.

## Contracts between the packages

- **Types on the wire are `purge-rpc`'s** (`purge_rpc::methods`, `purge_rpc::frame`). No hand-written
  DTO copies; if a type is missing in `purge-rpc`, add it there (with its schema test) rather than in a
  UI crate.
- **purge-client** exposes:
  - `EngineClient`: starts `purge-engine --stdio` (the port of `Stdio/EngineProcess.cs` +
    `StdioEngineClient.cs`: suspended start in a KILL_ON_JOB_CLOSE job, two inherited pipes, reader
    thread, id correlation), typed calls over `purge_rpc::methods`, notifications.
  - `BrokerClient`: the port of `Broker/*.cs` (launcher with `ShellExecuteExW("runas")`, random pipe
    name, `SECURITY_IDENTIFICATION`, server check, NDJSON, history/leftovers/stored-leftovers calls,
    the fingerprint store).
  - `SampleEngine`: the port of `Fake/FakeEngineClient.cs` and its sample JSON, for `--sample`.
  - Delivery: results and notifications arrive as a `ClientEvent` enum on a
    `std::sync::mpsc::Sender<ClientEvent>` given at start, plus a `wake: Arc<dyn Fn() + Send + Sync>`
    called after each send, so the UI loop wakes. Every call has an id; cancellation where the C# had it.
  - Engine and broker behind one trait each, so the UI and the models' tests can use a fake.
- **purge-ui-model** models take `purge_rpc` values in and give view state and request enums out;
  they never block, spawn or touch the toolkit. Their tests are the ports of `ui/Purge.Client.Tests`.
- **purge-ui** owns the loop, the drawing, the a11y tree and the wiring of client events into
  models.

## AutomationIds (the VM rig depends on them)

The a11y nodes carry the WinUI `x:Name`s the rig scripts find (`vm/guest/m3-e2e-ui.ps1`,
`m3-clean.ps1`): `ProgramList`, `UninstallButton`, `DUninstallButton`, `NavQueue`, `NavLeftovers`,
`MoveButton`, `MoveText`, `FooterCount`, `WaitingTitleText`, `WaitingCodeText`, `ResultTitleText`,
`ResultDetailText`, `UndoAllButton`, `UndoTitleText`, `UndoDetailText`, `EmptyTitle`, `InfoBarHost`,
plus ids for dialog buttons (the rig's ContentDialog lookups get updated in UI-SHIP).

## Packages and order

Wave 1 (parallel, each on its own branch from `ui/rust` in its own worktree):

1. **UI-SHELL** (`bins/purge-ui`): move the mockup's shell into the bin (host loop, a11y, rail, page
   host, title bar, launch markers, `--theme`/`--page`/`--sample` flags, panic hook and watchdog),
   build the look system (combined D1+D2 look, Bold look, colour presets × light/dark, transition
   setting with the new transitions, HC), settings persisted under `%LOCALAPPDATA%\Purge`, the full
   Settings page, the manifest and VERSIONINFO (`bins/versioninfo.rs`). Pages keep the mockup's drawing
   fed by placeholder data until wave 2.
2. **UI-CLIENT** (`crates/purge-client`): as above, with tests (the ports of `StdioEngineClientTests`,
   `BrokerClientTests`, `BrokerHelloTests`, `BrokerPipeTests`, `EngineLinkTests`). Security-relevant:
   Fable review before merge.
3. **UI-MODEL-A** (`crates/purge-ui-model`: `programs`, `pipeline`): `Model/*.cs` (Inventory,
   ProgramRules, ProgramEntries, RegistryLabel, Forecast), `Views/ProgramRow.cs` logic,
   `Pipeline/*.cs` (UninstallPipeline, UninstallQueue, RemovedLeftovers), with their tests.
4. **UI-MODEL-B** (`crates/purge-ui-model`: `leftovers`, `history`, `vault`): `Views/Leftovers/LeftoversModel.cs`
   and `LeftoversRow.cs`, `Model/Leftovers.cs`, `Views/HistoryModel.cs`, `Views/VaultModel.cs` and
   `VaultRows.cs`, `Shell/LeftoversNavigator.cs`/`LeftoversRequest.cs` logic, with their tests.

Wave 2: **UI-PAGES** (each page wired to models and clients: Programs with icons via `icon.batch`,
Uninstall + consent flow, Leftovers, History with undo, Quarantine, first-elevation and cancelled
bars), **UI-SHIP** (installer and release workflow build `Purge.exe` from `bins/purge-ui` instead of
`dotnet publish`; the rig's UI scripts updated; WinUI dropped), then the VM UI e2e and the launch
bench, then the a11y pass.

Pre-releases: the first once the shell runs the real engine with the Programs page, then one per
working page or fix batch.

## Rules for every package

- Worktree and branch are your own; never push, never touch `main`/`baseline` or the main checkout
  (`C:\Users\kaank\Desktop\uninstall\purge`). The coordinator merges.
- `CARGO_TARGET_DIR=E:\purge-target\ui` (shared, cargo locks it), `CARGO_HOME=E:\cargo-home`. Disk is
  tight: no other target dirs, no copies of build output.
- Gates before you hand back: `cargo fmt --all -- --check`, `cargo clippy -p <your crates> --all-targets
  -- -D warnings`, `cargo test -p <your crates>`.
- Never use VirtualBox or VBoxManage (VM runs are in progress). No new third-party crates without asking.
- Match the repo's conventions (docs/CONVENTIONS if present, the existing crates' style: doc comments
  that say why, no `unwrap` outside tests, errors as `thiserror` types).
- Commit on your branch in small commits with clear messages; end each message with the attribution
  lines you are given.
