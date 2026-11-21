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
| `w_titlebar` | `ExtendsContentIntoTitleBar` and `SetTitleBar` done. |
| `w_icon` | Window icon set. |
| `w_size` | `SizeAndCenter` done. |
| `programs_enter`, `programs_xaml` | `ProgramsView` constructor, before and after `InitializeComponent`. |
| `programs_ctor` | `ProgramsView` built and attached. |
| `rows_set` | `ItemsSource`/selection prepared (before `Activate()` when the reply is in). |
| `first_row` | First list container realized (`ContainerContentChanging`). |
| `first_tick` | First `CompositionTarget.Rendering` tick. |
| `presented` | After `DwmFlush()` on the dispatcher thread, i.e. the next committed frame after `first_tick`. |

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

## Gates

| Gate | Budget | Source |
|---|---|---|
| First Rendering tick vs the bare control | control p50 + 60 ms | 1.3 / 9.2 |
| First Rendering tick, absolute guard | 360 ms p50, 420 ms p90 | 1.3 |
| Names visible (presented frame with rows) | 400 ms p50, 460 ms p90 | 1.3 |
| First launch after install | 1.2 s p50 over 5 fresh copies | 1.3 (U3) |
| Cold after reboot | 1.0 s p50, N >= 5 | 1.3 / 9.2(e) |
| Regression | any p50 more than 10 % over the last result file of the same host fails the run | 9.2(b) |

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
```

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
| Cold after reboot (N = 5) | TBD | TBD | TBD | n/a | TBD |
| XAML changes, one at a time | TBD | TBD | TBD | TBD | TBD |

## Result locations

| Mode | File |
|---|---|
| Warm | `bench/launch/<YYYY-MM-DD>-<HHMMSS>-<COMPUTERNAME>.json` |
| First launch | `bench/launch/<YYYY-MM-DD>-<HHMMSS>-<COMPUTERNAME>-first-launch.json` |
| Cold | `bench/launch/cold-<COMPUTERNAME>.json` (a JSON array, one object per run with `at`, `uptime_s`, `presented`, `markers`) |

The warm file carries the host facts (OS, CPU/GPU, power/battery), the flavour, the actual arguments, the
`xaml_changes` under test, p50/p90/min/max per marker for both apps, the gate verdicts and the regression
list. The file name carries the local date and time, so several runs per day do not overwrite each other
or the regression baseline.

## Not done

- **TraceLogging.** 9.2(a) asks for the markers in TraceLogging as well as `PURGE_BENCH_OUT`; only the file
  exists.
- **Icons visible with a warm icon cache (1 s).** The stub engine sends no icons; the icon pipeline is
  M3-S1. The result file says so instead of measuring it.
- **DWM present-event cross-check.** The `presented` marker uses `DwmFlush`, not the `Microsoft-Windows-
  Dwm-Core` present events in WPR.
- **Defender-on check for the first-launch run.** The tool records the gate as "Defender state as on the
  host" but does not verify that real-time protection is on.
