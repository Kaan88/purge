# M3 launch bench

`cargo xtask bench-launch` measures how long the WinUI shell takes from process creation to the first
presented frame, against a bare-WinUI control in the same run. It belongs to package **M3-BENCH** and is
the evidence for the launch gates of ENGINE_PLAN.md 1.3 and 9.2. It is deliberately **not part of `xtask
ci`**: it needs published builds and a quiet machine.

## What is measured

Every launch is timed with markers relative to the process creation time the kernel recorded. Each marker
is one `name=milliseconds` pair; the app writes one line per launch to the file named by `PURGE_BENCH_OUT`
once the first frame has been presented. The markers, in launch order:

| Marker | Meaning |
|---|---|
| `module_init` | The marker module initializer, before `Main`. |
| `main` | The first line of the custom `Main`. |
| `engine_ready` | `engine.hello` answered (the stub until M3-STDIO). |
| `list_reply` | `programs.list` answered (300 rows after 20 ms under `--bench-stub`). |
| `on_launched` | `Application.OnLaunched`. |
| `window_ctor` | `MainWindow` constructor entered. |
| `w_backdrop` | `MicaBackdrop` set. |
| `w_icon` | Window icon set. |
| `w_size` | `SizeAndCenter` done. |
| `programs_enter`, `programs_xaml` | `ProgramsView` constructor, before and after `InitializeComponent`. |
| `programs_ctor` | `ProgramsView` built and attached. |
| `rows_set` | `ItemsSource`/selection prepared (before `Activate()` when the reply is in). When the reply comes in only during the title bar wait, it is marked after `w_titlebar`. |
| `first_row` | First list container realized (`ContainerContentChanging`). Since the pre-layout of the Programs page (see *Launch path*) this comes before `w_titlebar` and `Activate()` when the reply was in at `rows_set`, so it no longer shows that the first frame has rows (see `first_row_live`). |
| `first_row_live` | The first layout pass after the `MainWindow` constructor (the live layout `Activate()` starts, not the pre-layout) that finds a realized row container in the list. Reported, no gate. |
| `rows_at_tick` | A count, not a time: the row containers with a height in the list's items panel at `first_tick`. In the app's line only; `cargo xtask bench-launch` does not read it. |
| `w_titlebar` | `ExtendsContentIntoTitleBar` and `SetTitleBar` done. Since branch `m3-launch-perf` this is the last step of the `MainWindow` constructor, after `rows_set`, not after `w_backdrop`. |
| `first_tick` | First `CompositionTarget.Rendering` tick. |
| `presented` | After `DwmFlush()` on the dispatcher thread, i.e. the next committed frame after `first_tick`. |
| `names_visible` | The presented frame with rows: `presented` itself when `first_row` came before it (the stub, and a real list that was in by then), else `DwmFlush()` after the frame that follows `first_row`. Gated in `--real-engine` only. |
| `icons_visible` | The first screenful of rows (list height / 40 px) has its icons settled: applied from the atlas or the engine, or answered without one (that row keeps its tile); then `DwmFlush()`. Live engine only (the stub sends no icons). A failed icon request never marks it. |
| `s3_start`, `s3_open` | `--bench-s3 N`: the Leftovers page (S3) is asked for after the first frame (`s3_start`) and its list has a realized row in a presented frame (`s3_open`, after `DwmFlush()`). The S3 page open time is `s3_open - s3_start`. |
| `engine_fallback` | The engine could not be used and the sample data stands in; `--real-engine` refuses such a launch. |
| `bench_timeout` | The `--bench-until` marker did not come within 20 s of the first frame; the line is written as it is and the bench refuses it. |

The app writes its line when the marker named by `--bench-until` arrives (`presented` by default; also
`names_visible`, `icons_visible`, `s3_open`), and with `--bench-exit` then closes. With a live engine it
first lets the icon load finish (at most 10 s) so the icon atlas is saved for the next launch; the line
is already written, so this does not change the numbers.

Only `PURGE_BENCH_OUT` turns markers on: `LaunchMarkers.Enabled` is false in a normal run, where `Mark`
returns immediately and no process times are read.

The control app is `ui/bench/BareWinUI`, the least a WinUI 3 app can do (a Mica window with an empty
grid), built with the same flavour as `Purge.App` (unpackaged, self-contained, Native AOT, x64, custom
`Main`) and linked to the same `LaunchMarkers.cs`.

## How runs are counted

- Warm: `-n 21` launches of each app, alternating which app goes first in each pair; the first run of each
  app is dropped, leaving 20 samples per app. Percentiles are nearest-rank (p50 = 10th of 20, p90 = 18th).
- First launch after install: the publish folder is copied to 5 fresh directories; launches 1 to 5 are timed
  in each copy. The gated number is launch 1 of each of the 5 copies.
- Cold after reboot: one launch per reboot, appended to `cold-<host>.json`; the gate applies from 5 runs.
- Real engine (`--real-engine`): `-n 21` launches of `Purge.exe` alone, without `--bench-stub`, so the
  real `purge-engine --stdio` reads this host's ARP data. The run uses an icon atlas of its own (in the
  bench's temp directory, never `%LOCALAPPDATA%\Purge\icons.atlas`), empty at launch 1: launch 1 is the
  cold-icon-cache sample (reported) and is dropped from the warm numbers; launches 2 to 21 are warm.
- S3 page open (`--s3-open`): `-n 21` launches with the stub and a 2,000-item S3 fixture (the sample
  leftovers repeated with their own ids, every group and the Protected section in proportion), the
  first dropped.

## Gates

| Gate | Budget | Source |
|---|---|---|
| First Rendering tick vs the bare control | control p50 + 60 ms | 1.3 / 9.2 |
| First Rendering tick, absolute guard | 360 ms p50, 420 ms p90 | 1.3 |
| Names visible (presented frame with rows), stub | 400 ms p50, 460 ms p90 on `presented`, rows before it in every run | 1.3 |
| Names visible (presented frame with rows), real engine and ARP data (`--real-engine`) | 400 ms p50, 460 ms p90 on `names_visible` | 1.3 / M3 9.1 |
| Icons visible, warm icon cache (`--real-engine`) | 1 s p50 on `icons_visible`; the cold cache (launch 1) is reported | M3 9.1 |
| S3 page open, 2,000-item fixture (`--s3-open`) | reported, no gate yet | M3 9.1 |
| First launch after install | 1.2 s p50 over 5 fresh copies | 1.3 (U3) |
| Cold after reboot | 1.0 s p50, N >= 5 | 1.3 / 9.2(e) |
| Regression | any p50 more than 10 % over the last result file of the same host and mode fails the run (stub: `first_tick`, `presented`; real engine: `names_visible`, `icons_visible`) | 9.2(b) |

`OptimizeApplyStyles` stays off on Windows App SDK 2.6.5 (ContentDialog regression) and `--xaml-changes`
refuses it by name, like any name outside the three of 9.2 step 8.

## Timing method and its known biases

- Markers are `GetSystemTimePreciseAsFileTime` values minus the `GetProcessTimes` creation time, both
  FILETIME and therefore **wall clock, not a monotonic counter**. A clock step between process creation and
  the marker (NTP, a manual change) distorts that launch. The 100 ns unit is finer than the real resolution.
- `presented` is an approximation: `DwmFlush()` waits for the next DWM composition after the first tick,
  and the marker is taken immediately after it on the dispatcher thread, **before** the deferred first-tick
  work (`ProgramsView.OnFirstTick`). It is not a Dwm-Core present-event timestamp; the WPR cross-check in
  9.2(a) is not implemented (see *Not done*).
- The wait before the cold launch is `GetTickCount64` uptime plus a one-second CPU-idle sample
  (`GetSystemTimes`). The tool warns rather than refuses when the machine is busy.
- The machine is a shared dev host. Any other build, indexer or browser invalidates a run; the result file
  records the host and the power/battery state so a suspicious run can be recognised later.

## Launch path

Facts the launch-time work in branch `m3-launch-perf` rests on, measured on the bench laptop (i7-6700HQ,
Intel HD 530 + GTX 960M) with extra markers in builds that were not committed:

- The first `ExtendsContentIntoTitleBar` call blocks the UI thread until the window's composition is ready.
  Moving the call later in the constructor does not move the time it returns (it returns at about the time
  the bare control has its first Rendering tick); the UI thread is busy for only about a quarter of that time
  (`QueryThreadCycleTime`). A `D3D11CreateDevice` on a thread of its own, started in `Main`, took about
  210 ms on this laptop and made the wait longer, not shorter. Creating a `Window` or asking for the
  compositor earlier did not change when the wait ends.
- `AppWindow.TitleBar.ExtendsContentIntoTitleBar` blocks the same way. Calling either after `Activate()`
  (with or without cloaking the window) ends later than calling it before, and the layout still waits.
- So the `MainWindow` constructor now builds the Programs page, loads the rows and lays the page out once
  (`PreMeasurePrograms`) before that call, all inside the wait, and only then extends the title bar; the
  window is still not shown before `Activate()`. What is left after the wait is `Activate()`, the live
  layout of the whole window and the first render. The pre-layout applies the templates but realizes only
  one row container (counted at the end of the constructor in a diagnostic build); the live layout
  realizes the first screenful.
- Rows in the first frame: `first_row` now fires in that pre-layout, so the stub's "rows before it in
  every run" check no longer shows much. `first_row_live` and `rows_at_tick` (report only) do: in an
  interleaved stub run against the previous commit (n=14, run d71f7587) `first_row_live` came before
  `first_tick` (p50 421 ms vs 424 ms) and `presented` in 14 of 14 launches, and 15 rows were realized at
  `first_tick` in every launch. A screen capture of a launch (`Graphics.CopyFromScreen` of the window
  rectangle polled from the moment the window is visible) shows the window black until the first frame
  with content, and that frame already has the header, the tabs and the first screenful of rows (no tab
  counts, sizes or details pane yet; they come after the first tick). In that capture the content
  appeared 70-90 ms after the `presented` marker; a GDI screen copy takes about 20 ms and the window
  open animation runs at the same time, so this is not a measure of `presented`.
- The rows of the first list are built and sorted on the thread that read the `programs.list` reply
  (`ProgramsView.Prepare`, the same filter and sort as `Refresh`), so a real engine's reply that comes in
  during the wait costs the UI thread almost nothing after it.
- The program `ListView` has no container transitions until `OnFirstTick`, which restores the ListView
  defaults. Checked at run time with screen captures of the list after a tab switch: the rows animate for
  about 600 ms with the same frame-by-frame curve as fa3ba36, and without the restore they snap in one
  frame. The items panel's own `ChildrenTransitions` is empty both here and on fa3ba36; the
  `ItemsStackPanel` takes the transitions from the ListView, so that count is not the thing to check.
- The title bar theme (`AppWindow.TitleBar.PreferredTheme`) is now set before `ExtendsContentIntoTitleBar`.
  With `--theme light` and `--theme dark` (system theme dark) the caption buttons' glyphs are the same as on
  fa3ba36: black on light, white on dark (screen captures of the button area).
- Measurement noise: two copies of the same build, interleaved (A/A, run c970ae85), differed by about
  12-14 ms of paired p50 difference on the VM-loaded host. A per-commit difference at or below that is not
  shown to be a gain on its own. The interleaved figures in this section and in DECISIONS come from a
  development driver (`ab.ps1`) that takes interpolated percentiles; `cargo xtask bench-launch` and the
  gates use nearest rank.
- Without `ExtendsContentIntoTitleBar` at all (the system caption; a design change, not made) `Activate()`
  and part of the layout run inside the wait: in an interleaved run on a loaded host this was 93 ms
  earlier on `first_tick` and `presented` than the extended title bar with the changes above.
- Tried and not kept, each within the noise of interleaved runs on a loaded host: the three XAML optional
  changes of 9.2 step 8, no `x:Phase` on the size column, two plain `TextBlock`s for the name cell, the
  sort `DropDownButton` hidden, `SelectedItem` set after the first tick, `SelectionMode="Single"`.

## Running it

From the repository root, on a quiet machine, Defender real-time on:

```powershell
# 0. Publish both apps (AOT needs the VS Build Tools C++ workload)
& "C:\Program Files\dotnet\dotnet.exe" publish ui\Purge.App -c Release -r win-x64 -o out\purge
& "C:\Program Files\dotnet\dotnet.exe" publish ui\bench\BareWinUI\BareWinUI.csproj -c Release -r win-x64 -o out\bare

# 1. Warm, interleaved, 21 pairs (the first is dropped)
cargo xtask bench-launch --purge out\purge --bare out\bare

# 2. One XAML optional change at a time, then keep only measured gains
cargo xtask bench-launch --purge out\purge --bare out\bare --purge-args "--xaml-changes IconNoGridOptimization"
#    and the same with DefaultStyleOptimizations and DeferContextFlyoutInit

# 3. First launch after install: 5 fresh copies, launches 1-5
cargo xtask bench-launch --first-launch --purge out\purge

# 4. Cold after reboot: one run per reboot, five reboots in all
cargo xtask bench-launch --cold --reset --purge out\purge   # the first run of a new series
cargo xtask bench-launch --cold --purge out\purge           # after each of the next four reboots

# 5. Names and icons visible with the real engine and this host's ARP data
cargo build --release -p purge-engine
Copy-Item target\release\purge-engine.exe out\purge\
cargo xtask bench-launch --real-engine --purge out\purge   # or --engine <path to purge-engine.exe>

# 6. S3 page open on the 2,000-item fixture (reported, no gate)
cargo xtask bench-launch --s3-open --purge out\purge
```

`--real-engine` and `--s3-open` take `-n`, `--out`, `--no-write`, `--power` and `--purge-args` like the warm
run, need no `--bare`, and refuse `--purge-args` that carry `--bench-stub`, `--sample`, `--bench-exit`,
`--bench-until` or `--bench-s3` (the mode sets those). A real-engine launch that shows the sample data
(`engine_fallback`) or times out fails the run.

`cargo xtask bench-launch` prints the result JSON on stdout and exits 0 on pass, 1 on a gate breach or a
regression.
`--no-write` prints without writing a file; `--out <dir>` moves the results (default `bench/launch`).

### Cold-after-reboot procedure (five reboots)

1. Reboot the host; log on and let it settle for 120 s with no other work (the tool waits for 120 s of
   uptime itself, and warns if the CPU is not mostly idle).
2. Run `cargo xtask bench-launch --cold --purge out\purge` once. Nothing else runs on the machine.
   On the first run of a new series add `--reset`: it clears the old series and records this run as
   run 1.
3. Repeat steps 1-2 four more times (without `--reset`); the fifth run completes the series.
4. From the fifth run the tool gates `presented` at 1.0 s p50 and exits 1 on a breach.

One run per reboot only: a second run without a reboot is a warm launch and corrupts the series. Do not
rebuild or republish between the reboots; the numbers would no longer describe one image.

## Results

The result files are committed under `bench/launch/` and summarised here.

| Run | Date | File | p50 | p90 | Verdict |
|---|---|---|---|---|---|
| Warm, Purge | TBD | TBD | TBD | TBD | TBD |
| Warm, bare control | TBD | TBD | TBD | TBD | TBD |
| First launch after install | TBD | TBD | TBD | n/a | TBD |
| Names visible, real engine (`--real-engine`) | TBD | TBD | TBD | TBD | TBD |
| Icons visible, warm icon cache (`--real-engine`) | TBD | TBD | TBD | TBD | TBD |
| Icons visible, cold icon cache (`--real-engine`, launch 1) | TBD | TBD | TBD | n/a | reported |
| S3 page open, 2,000 items (`--s3-open`) | TBD | TBD | TBD | TBD | reported |
| Cold after reboot (N = 5) | 2026-11-22 | `bench/launch/cold-DESKTOP-K1F333G.json` (laptop, fe444fd publish) | 559.7 ms | n/a | PASS (limit 1000 ms; runs 544-584 ms, CPU 96-98 % idle) |
| XAML changes, one at a time | TBD | TBD | TBD | TBD | TBD |

## Result locations

| Mode | File |
|---|---|
| Warm | `bench/launch/<YYYY-MM-DD>-<HHMMSS>-<COMPUTERNAME>.json` |
| First launch | `bench/launch/<YYYY-MM-DD>-<HHMMSS>-<COMPUTERNAME>-first-launch.json` |
| Real engine | `bench/launch/<YYYY-MM-DD>-<HHMMSS>-<COMPUTERNAME>-real-engine.json` (schema `purge.bench-launch-real/0`) |
| S3 page open | `bench/launch/<YYYY-MM-DD>-<HHMMSS>-<COMPUTERNAME>-s3-open.json` (schema `purge.bench-launch-s3/0`) |
| Cold | `bench/launch/cold-<COMPUTERNAME>.json` (a JSON array, one object per run with `at`, `uptime_s`, `presented`, `markers`) |

The warm file carries the host facts (OS, CPU/GPU, power/battery), the flavour, the actual arguments, the
`xaml_changes` under test, p50/p90/min/max per marker for both apps, the gate verdicts and the regression
list. The file name carries the local date and time, so several runs per day do not overwrite each other
or the regression baseline.

## Not done

- **TraceLogging.** 9.2(a) asks for the markers in TraceLogging as well as `PURGE_BENCH_OUT`; only the file
  exists.
- **Icons visible in the stub runs.** The stub sends no icons; `--real-engine` measures `icons_visible`.
  Its warm cache is the run's own atlas after launch 1, not the user's atlas (which may be older or
  hold other programs).
- **DWM present-event cross-check.** The `presented` marker uses `DwmFlush`, not the `Microsoft-Windows-
  Dwm-Core` present events in WPR.
- **Defender-on check for the first-launch run.** The tool records the gate as "Defender state as on the
  host" but does not verify that real-time protection is on.
