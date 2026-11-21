# M3-UI-CLIENT: writer notes

Package: `ui/Purge.Client` RPC clients, broker launcher, server check. Branch `m3-ui-client`, cut from
`baseline` 2ec05f2. Nothing is wired into `Purge.App` at start; the first Uninstall, Restore or History-detail
click calls the launcher.

## Shape

| File | What |
|---|---|
| `ui/Purge.Client/Broker/BrokerRpcClient.cs` | NDJSON JSON-RPC over the broker pipe: requests, typed results from `RpcJsonContext`, notifications, `$/cancel`, errors, link end. `engine.hello` and `broker.shutdown` have typed helpers; every other method goes through `CallAsync`. |
| `ui/Purge.Client/Broker/BrokerServerCheck.cs` | The client half of design 3.3 step 3: `GetNamedPipeServerProcessId` equals the pid `ShellExecuteExW` returned, the image is the launched broker, the token is elevated. |
| `ui/Purge.Client/Broker/BrokerLauncher.cs` | `TokenElevationType` pre-check, 128-bit pipe name, `ShellExecuteExW("runas")` on an STA thread, connect with `SECURITY_IDENTIFICATION`, server check, exit-code/timeout/cancel results, `AllowSetForegroundWindow` before a consent request. |
| `ui/Purge.Client.Tests/BrokerClientTests.cs` | Framing round trip, notifications, cancel, error kinds, a server that ends, the server check against a pipe served by the test process, error 1223. |

No existing file changed. `StdioEngineClient` is left for M3-UI-S1 to move onto `Rpc/`; the broker client uses the
same newline framing and the same `RpcJsonContext` DTOs.

## Choices (DECISIONS candidates)

1. **New files only.** The broker client does not refactor `StdioEngineClient`, so the Programs-page work in
   M3-UI-S1 and this package do not share a file.
2. **Check before the first byte.** `BrokerPipe.TryOpen` (called by `BrokerLauncher`) connects with `CreateFileW` (`FILE_ATTRIBUTE_NORMAL |
   FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`), runs `BrokerServerCheck` on the raw handle, and only then
   makes the `NamedPipeClientStream` (`isAsync: true, isConnected: true`) and `BrokerRpcClient`. A refused server never reaches a DTO parser.
   The handle must be overlapped (review M3-R2 B2): the reader thread is always inside a read, the broker sends nothing before
   `engine.hello`, and Windows serialises I/O on a synchronous handle, so a synchronous handle never sends the hello.
   `BrokerPipeTests` runs the hello against the real Rust pipe server (`bins/purge-broker/examples/pipe_harness.rs`, unelevated,
   an example target with no release build) and against an in-process server that stays in a pending read.
3. **Pid, image, elevation.** The pid must equal the process handle from `ShellExecuteExW` (held, so the pid
   cannot be reused); `QueryFullProcessImageNameW` must equal the launched path (ordinal, case-insensitive); the
   process token's `TokenElevation` must be set. On a failure the launched process is terminated, because it is
   still ours, and nothing is shown from it.
4. **Account pre-check.** `TokenElevationType` `Limited` (split administrator) or an elevated `Full`/`Default`
   token may launch; a non-elevated `Default` token is `NotAdministrator` and starts nothing.
5. **UAC.** `ShellExecuteExW("runas")` runs on a dedicated STA thread with `SEE_MASK_NOCLOSEPROCESS |
   SEE_MASK_NOASYNC`, owner = the caller's window, `SW_SHOWNORMAL` (the broker has no window of its own, so
   nothing appears apart from its dialogs; S7). Error 1223 is `BrokerLaunchStatus.Cancelled`, which
   feeds `Purge.App/Shell/ElevationPrompts.CancelledBar`; the launcher shows nothing itself.
6. **Exit before the pipe.** The connect loop polls for 10 s; if the process has exited, the result carries its exit
   code and the text says so. Other connect errors carry the Windows error and its message.
7. **Cancel.** One cancellation sends `$/cancel {request}` and ends that call, like the stdio client; the link
   stays open. The broker's mutating requests that ignore cancel keep running, as its design says.
8. **Foreground.** `BrokerSession.AllowForeground()` calls `AllowSetForegroundWindow(broker pid)`; the caller does
   this before `plan.execute` and the other consent requests. A refusal is not an error.

## Still needs the VM

- The broker through a real `runas` UAC prompt, then `BrokerRpcClient.HelloAsync` over the real elevated pipe and
  the server check on the real broker (pid, image, elevation).
- "No" at the Windows prompt (error 1223) showing the cancelled bar and starting no broker; a standard user
  refused before any prompt.
- The broker exiting before its pipe (bad arguments, an untrusted install, data root) surfacing its exit code.
- `AllowSetForegroundWindow` and the broker's TaskDialog coming to the foreground; a cancel of the prompt by
  closing the broker does not touch the UI.
- A squatter on the pipe name (server check refuses it) and a broker that dies between connect and hello.
- Re-launch after an idle exit with `leftovers.scan` and re-ticking by `CandidateId` (the flow package owns the
  scan call; the launcher already starts a fresh broker and pipe).

## Open points

- The re-scan/re-tick after an idle exit is launcher-ready but the flow package has to call it; this package has no
  review/session state to restore.
- The stdio client's notification surface is still the one M3-STDIO wrote; if the flow package needs more stdio
  notifications, it belongs with the M3-UI-S1 move onto `Rpc/`.
- `purge-broker.exe` was a console binary; it is now built for the Windows subsystem and the launcher passes
  `SW_SHOWNORMAL`, so no console appears and the consent dialog is the first window (S7; verify on the first
  elevated run that the dialog is visible and in front).
