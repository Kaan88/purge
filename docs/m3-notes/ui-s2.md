# M3-UI-S2: Uninstall pipeline page

Package: `ui/Purge.App/Views/Uninstall/**`, `ui/Purge.Client/Pipeline/UninstallPipeline.cs`,
`ui/Purge.App/Shell/LeftoversRequest.cs`, branch `m3-ui-s2`, cut from `baseline` ae35e06 (M3-BROKER-FLOW merged).

## Shape

| File | What |
|---|---|
| `ui/Purge.Client/Pipeline/UninstallPipeline.cs` | `UninstallController` (the page's view model) and the two seams: `IUninstallBroker` (prepare/run/observed/scan) and `IMediumUninstall` (route/run_user). `BrokerUninstallClient` is the product link over a checked `BrokerSession`; `EngineMediumUninstall` wraps `IEngineClient`. No XAML, so the tests drive every step with scripted links. |
| `ui/Purge.App/Views/Uninstall/UninstallView.xaml(.cs)` | The page: program card, five-step stepper, running-process line with "Check again", safety net (quiet, restore-point choice), bars, confirm dialog. All state comes from the controller; no binding. |
| `ui/Purge.App/Shell/LeftoversRequest.cs` | The S2 → S3 hand-off: `LeftoversRequest` (program, session, scan, mode, quiet, restore point, live `BrokerSession`) and `ILeftoversPage`. |
| `ui/Purge.App/Shell/LeftoversNavigator.cs` | Opens the cached `ReviewView` and calls `ILeftoversPage.Show`; if this build's page does not take requests, closes the broker and reports false. |
| `ui/Purge.Client/Broker/BrokerRpcClient.cs` | `BrokerRpcException.Details` carries the whole `error.data`, so an `uninstall_failed` keeps its exit code and `forced_offered`. |
| `ui/Purge.Client/IEngineClient.cs`, `Stdio/StdioEngineClient.cs` | `uninstall.route` and `uninstall.run_user`; `uninstall.progress` notifications feed the per-call callback. `CanChangePc` is true for a live engine. |
| `ui/Purge.App/Views/ProgramsView.xaml.cs` | Uninstall is enabled for a live engine and calls `MainWindow.OpenUninstall().Begin(...)`; the old sample dialog and `ReviewView.ScanAsync` call are gone. |
| `ui/Purge.App/MainWindow.xaml.cs` | `"queue"` maps to `UninstallView`, plus `OpenUninstall()` and `DialogRoot`. No other shared change. |

`Views/QueueView.xaml(.cs)` (the stopgap sample page) is deleted.

## Choices (DECISIONS candidates)

1. **UAC on the click, broker only then.** The click shows the first-elevation explanation, then
   `BrokerLauncher.LaunchAsync`; nothing at app start touches the broker. A cancelled prompt shows the cancelled bar
   and starts nothing.
2. **Route from the broker, command from the runner.** `uninstall.prepare` decides the route. For a broker route the
   dialog shows the frozen prepare command; for a medium route the page asks the engine `uninstall.route` and shows the
   engine's command and signer, because the engine is the process that runs it (`run_user` derives the same lines from
   the same inventory). The quiet flag travels unchanged to `uninstall.run` / `uninstall.run_user`, so the shown line
   is the run line.
3. **Order.** Medium route: `prepare` → `run_user` → `observed` → `leftovers.scan`; broker route: `prepare` → `run` →
   `leftovers.scan` (the run result already carries verify-gone). A failed or unverified uninstall scans `forced`.
4. **Forced cleanup.** `uninstall_failed` (broker, with `error.data.exit_code` and `forced_offered`) or a failed
   `run_user` outcome leaves the session open and offers "Run forced cleanup" and "Retry". Forced cleanup is
   `leftovers.scan {forced: true}` with nothing pre-selected, then the ordinary S3 hand-off.
5. **The broker session survives into S3.** The page takes the broker out of the controller (`TakeBroker`) and puts the
   `BrokerSession` in `LeftoversRequest`; S3 owns it from then on. The controller then never closes it.
6. **No new first-frame element.** The page is built on the first navigation, and its bars/dialog on demand.
7. **No close/end-task/restart control.** The running line is text plus "Check again"; a restart request is an
   informational bar.

## Tests

`ui/Purge.Client.Tests/UninstallPageTests.cs` drives `UninstallController` with a scripted launcher, broker and medium
engine: both routes and the exact command each runs, a quietless program, cancelled UAC, a standard user, a broker
that exits before its pipe, a medium prepare whose engine disagrees (wrong_route), a broker run refused with
wrong_route, a failed broker uninstaller with the forced cleanup (scan forced), a failed medium uninstaller (observed
first), still-installed → forced, a restart, a broker that dies mid-run (start over relaunches and disposes the dead
link) and an engine that dies mid-run.

`ui/Purge.Client.Tests/UninstallClientTests.cs` covers the stdio link (`uninstall.route`, `uninstall.run_user` with
three progress notifications, `wrong_route`, a link that dies) and the broker's `error.data` parsing for
`uninstall_failed`.

## Still needs the VM

- A real `runas` prompt from this page, both routes: VS Code (system, broker) and VS Code (user, medium) on the M3
  VMs; the command shown equals the command that ran (Process Explorer / the uninstaller's log).
- A "No" at the Windows prompt showing the cancelled bar, and a standard user refused before any prompt.
- A real failed uninstaller (a locked app, exit code 1603) offering the forced cleanup, and the forced scan's
  pre-selection being empty on the leftovers page.
- The broker dying mid-uninstaller (kill it from Task Manager) and the broker exiting before the pipe (bad install
  layout); the page's bars and Start over.
- The engine dying mid-uninstaller (kill `purge-engine.exe`); "Restart Purge".
- A running-process hint with a real process, "Check again" after closing it, and prepare/route re-reading it.
- A restart-required uninstaller (3010) and the text-only restart bar.
- The S3 hand-off after the merge: the real leftovers page taking the live broker and showing the scan it was handed.

## Open points

- **Queueing.** The page runs one program per Uninstall click. `UninstallView.Begin` takes one `UninstallTarget`; the
  next app can only start after the review returns, which is S3's state. A queue across reviews needs a cross-package
  owner; the controller already serialises one run at a time, so the queue can be layered later without changing the
  protocol calls.
- **S3 contract.** `ILeftoversPage.Show(LeftoversRequest)` is this package's proposal for the S3 hand-off. S3 must
  implement it on `ReviewView`; until then the navigator closes the broker and the page shows its own bar.
- **`ObservedParams` outcome.** M3-EXEC may add the medium run's outcome to `uninstall.observed`. The page uses the
  current DTOs: a failed `run_user` is known from its result, so forced mode is correct across the two processes for
  this UI already. If M3-EXEC changes the scan mode rule, this page's `forced` choice still asks for forced.
- **Restore point made line.** S2 never makes a restore point (the executor does, at `plan.execute`). The XAML row is
  present and collapsed; S3 (or a later S2 change that receives the outcome) sets it.
- **Settings.** "Prefer quiet" and the restore-point default are not read from the settings file yet (M3-UI-SETTINGS);
  the page starts quiet when the program offers it and at High risk.
