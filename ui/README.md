# ui: Purge desktop app

The full WinUI 3 app lands in **M3** (ENGINE_PLAN.md §11.1). What is here now is the **shell skeleton**: the
window, the left rail and every mockup screen on sample data: S1 Programs, S2 Uninstall queue, S3 Leftover
review, S4 History & undo, S5 Settings, S6 Assistant, and a preview of the security prompt (from S3's quarantine
button). Startup is a placeholder (after v1). The look follows the private "Purge UI mockups" canvas; shared
styles live in `Purge.App/Shell/Styles.xaml`. Nothing is wired to the engine (`Purge.Client` has a stub), and no
button changes anything on the PC.

Projects (§3.2):
- `Purge.App/`: the window (`Purge.exe`). Custom `Main` (`Program.cs`) starts the engine request before any XAML
  init, then starts XAML.
- `Purge.Client/`: `IEngineClient` (one method per JSON-RPC call used so far) and `FakeEngineClient`, which
  answers from embedded sample JSON shaped like `purge.inventory/0` (`Fake/sample-inventory.json`). The DTOs in
  `Model/` are hand-written for now; in M3 NJsonSchema generates them from the `schemars` output of `purge-model`,
  and a stdio NDJSON JSON-RPC transport replaces the fake.

Stack (decided, §9.1):
- C# on .NET 10 with WinUI 3, Windows App SDK 2.6.x, unpackaged, self-contained, Native AOT, x64.
- Component packages only (`Microsoft.WindowsAppSDK.WinUI` + `.Runtime` 2.6.5), not the metapackage.
- TFM `net10.0-windows10.0.19041.0` (CsWinRT 2.x) until microsoft-ui-xaml #12625 is fixed.
- Runs `asInvoker`; elevation goes through the on-demand `purge-engine --broker`, which also shows the
  final consent dialog.
- WinAppSDK 2.0 servicing ends 2027-04-29: an upgrade and launch re-bench is scheduled in M3+.

## Build and run

Needs the .NET 10 SDK (10.0.4xx) and, for the Native AOT publish, Visual Studio 2026 (or Build Tools) with the
"Desktop development with C++" workload. NuGet packages come from nuget.org only.

```powershell
# Debug build (JIT). Fast to iterate; output in Purge.App\bin\Debug\net10.0-windows10.0.19041.0\win-x64\
dotnet build ui\Purge.slnx
ui\Purge.App\bin\Debug\net10.0-windows10.0.19041.0\win-x64\Purge.exe

# Release: Native AOT, self-contained (about 95 MB folder; Purge.exe itself is a 7 MB native binary).
dotnet publish ui\Purge.App -c Release -r win-x64 -o <out-dir>
<out-dir>\Purge.exe
```

If the AOT link step fails with `'vswhere.exe' is not recognized`, put the VS installer folder on `PATH` first:
`$env:PATH = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer;$env:PATH"`.

Development switches (no effect on normal use):

| Switch | Effect |
|---|---|
| `--theme light` / `--theme dark` | Override the Windows theme for this run (Settings → Appearance does the same at run time). |
| `--page <key>` | Open on `programs`, `queue`, `leftovers`, `history`, `assistant` or `settings`. |
| `--bench-exit` | Close right after the first presented frame (launch bench). |

Launch markers (§9.2 (a)) are milliseconds since process creation: `main`, `list_reply`, `on_launched`,
`window_ctor`, `first_tick` (first `CompositionTarget.Rendering`), `presented` (approximate: one `DwmFlush` after
the first tick; WPR with Dwm-Core present events gives the exact value). They are shown in Settings →
About, and appended as one line per launch to the file named by `PURGE_BENCH_OUT`.

## Notes for M3

- Under Native AOT, casting a `Style` or `Brush` looked up from code (`Resources["key"]`) throws
  `InvalidCastException` (the JIT build works). Keep theme resources in XAML (`{ThemeResource}`) and toggle
  `Visibility` instead.
- Buttons whose content is not a plain string need `AutomationProperties.Name` (rail, icon buttons).
- The rail is plain Buttons in a `StackPanel` (§9.4), not a `NavigationView`.
- S1 follows the mockup, not §9.2's budget: 52 px rows (not 40) with a letter tile, a two-line name, an
  installer chip, version, size and date: about 11 elements per row where §9.2 asks for ≤ 5. Cost on the dev
  host: warm presented p50 332 → 340 ms. Revisit when real icons land, before the gates are frozen.
- `Purge.App/Assets/Purge.ico` is a placeholder icon, drawn by `Assets/gen_icon.py`.
- Anything given to `ItemsSource` must be a `List<T>` or `ObservableCollection<T>`. A collection expression
  assigned to `IReadOnlyList<T>` becomes a compiler-made type that CsWinRT rejects ("Value does not fall within
  the expected range"), on JIT and AOT alike.
- Screens other than S1 are built on navigation, so they don't change launch time (warm presented p50 338 ms
  with all screens in).
- The security prompt here is a `TaskDialogIndirect` shown by the window (needs the Common Controls v6
  manifest dependency). In M3 the broker shows it at high integrity; `Shell/ConsentPrompt.cs` is the layout to port.
  It now has Quarantine / Delete / Restore variants (`ConsentAction`).
- Board pages added on navigation only: Home (14), Quarantine vault (16), Footprint (09), the time strip on
  History (13), the safety dial in Settings (17), the inline Ask button in Leftovers (22, off by default, turn
  on in Settings or with `--inline-ask`) and the command palette in the title-bar search box (05, Ctrl+K;
  `--query "text"` types into it for tests). The three new rail buttons cost about 3 ms (interleaved A/B, n=16).
- Under Native AOT, `ListView.ContainerFromIndex/Item` returns the container projected as `ContentControl`,
  so `as ListViewItem` is null. Cast to `FrameworkElement`.
- A `LinearGradientBrush` with `SpreadMethod="Repeat"` corrupts rendering of the whole region. Hatching in
  Footprint is drawn as clipped `LineGeometry` lines instead.
- Never test with global keystrokes (SendKeys): drive the app through UI Automation patterns and the
  `--page` / `--query` flags.
- Data marked SAMPLE in the UI (removed-outside-Purge, orphaned companions, assistant answers, expected
  leftovers) has no engine call yet.

All UI text is Purge's own. `cargo xtask ui-strings` checks every `*.cs` string literal and `*.xaml`
attribute value of 12+ characters here.
