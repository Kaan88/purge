# Trying Purge inside Sandboxie

This page is for a developer who wants to try the whole Purge path on a normal PC, with the real engine,
without a VM: list programs, uninstall one, review the leftovers, move them to quarantine, undo.
It uses a special engine build, the **sandbox dev build**, and Sandboxie-Plus.

The sandbox dev build is not a product build. Never ship it and never use it outside Sandboxie.

## What the sandbox dev build is

It is `purge-engine` built with the Cargo feature `sandbox-dev`. Compared with a release engine:

- It has the executor verbs (`exec`, `undo`, `journal resume`, `journal rollback`, `quarantine purge`).
  A release engine does not have them yet.
- It keeps its quarantine, journals and sessions in a **relaxed store**: a folder owned by the current user,
  with no administrator ACLs. The folder is `%PURGE_SANDBOX_DEV_ROOT%` when that variable is set
  (it must be an absolute path), else `%LOCALAPPDATA%\PurgeSandboxDev`. `exec` creates it the first time.
- It does not need administrator rights.
- It **refuses every verb that changes something** unless the process runs inside Sandboxie. The verbs are
  `uninstall`, `exec`, `undo`, `journal resume`, `journal rollback`, `journal retry-held` and `quarantine purge`. The engine
  checks whether `SbieDll.dll` is loaded in its own process; Sandboxie loads that DLL into every process it
  runs. Outside Sandboxie these verbs stop at once with exit code 13 and this message:
  `this is a SANDBOX DEV BUILD and the process is not running inside Sandboxie (SbieDll.dll is not loaded);
  start it in a Sandboxie box. Nothing was done.`
- The read-only verbs (`inventory`, `harvest`, `scan`, `journal recover`, `journal show`,
  `quarantine expiring`) work anywhere.
- Exit code 12 means something else in every build: the session was not closed, or its report or index
  entry was not written. The app then offers Resume to finish the record.
- `purge-engine --version` prints `SANDBOX DEV BUILD` on its last line, and `--help` ends with code 13.
  The app shows the same words in its title bar and in Settings, About.

## Build it

Run these from the repository root.

```
cargo build -p purge-engine --release --features sandbox-dev
dotnet publish ui\Purge.App\Purge.App.csproj -c Release -r win-x64 -o <out>
```

Then copy `target\release\purge-engine.exe` into `<out>`, next to `Purge.exe`, and copy `kb\baselines\*.tsv.gz`
into `<out>\kb\baselines\`. The scan uses the baseline of your Windows build when there is one.

The publish is self-contained (Native AOT, Windows App SDK included), so the PC that runs it needs no
.NET runtime and no Windows App SDK runtime. Building it needs the .NET 10 SDK and the Visual Studio C++
build tools (the AOT linker). If the publish fails with `'vswhere.exe' is not recognized`, put
`C:\Program Files (x86)\Microsoft Visual Studio\Installer` on `PATH` for that shell and run it again.

The app looks for the engine next to `Purge.exe`. To use another engine, set `PURGE_ENGINE_EXE` to its full
path. Start the app with `--sample` to see the sample data instead of the engine.

## Make the box

Install Sandboxie-Plus from its official site. In Sandboxie-Plus, create a new box, for example `PurgeTest`:

- Type: a normal **Standard Sandbox**. Do not use an application compartment box: it does not isolate the
  file system and the registry, so the test would change the real machine.
- **Drop rights**: leave "Drop rights from Administrators and Power Users groups" **off**. Purge itself does
  not need administrator rights in this build, but the installer and the uninstaller of the test program
  often do, and with dropped rights they fail or behave differently from a real run.
- Leave file and registry virtualisation at the defaults. Do not add the Purge folder or the test program's
  folders to "Open file access": an open path writes through to the real machine.
- Optionally turn on "Delete content when the last process in the box ends". Without it the box keeps your
  test state between runs, which is useful to try Undo later.

The box's files are by default under `C:\Sandbox\<your user name>\PurgeTest\`. The registry of the box is in
the `RegHive` file in the same folder.

## Start the app in the box

Either right-click `Purge.exe`, choose "Run Sandboxed" and pick the box, or run:

```
"C:\Program Files\Sandboxie-Plus\Start.exe" /box:PurgeTest "<out>\Purge.exe"
```

The window title must say `SANDBOX DEV BUILD`. Sandboxie also draws its border around a sandboxed window
when that option is on.

## What to try

1. **Install a small test program inside the same box.** Start its installer with "Run Sandboxed" in
   `PurgeTest`. A small Inno Setup, NSIS or MSI program is best. It then exists only in the box.
2. **Programs.** Press Refresh. The list now has the test program. The list comes from the engine.
3. **Uninstall.** Select the program and choose Uninstall. Purge asks first, then runs the program's own
   uninstaller in quiet mode, then scans for leftovers. While it runs, the page shows the step (recording,
   uninstalling, scanning) and the seconds spent, every second, with a Cancel button. A forced scan of
   Notepad++ on a normal PC takes about 20 seconds (12 s recording, 9 s scanning); the uninstaller adds
   its own time.
   "Force remove" skips the uninstaller and only scans.
4. **Review.** The page shows each item with its band (safe, likely, weak, protected) and the engine's
   reason. The engine has ticked what it would remove. Tick or untick items.
5. **Move to quarantine.** Press the move button. Purge says how many items it will move, that they go to
   quarantine and that you can undo it. Confirm. The page shows the seconds spent and a Stop button;
   stopping a move leaves a journal, and the page then offers Resume or Roll back. The result says what was
   moved, skipped or failed.
6. **Vault.** Open the vault. The session is listed. Press Undo to put everything back.
7. **Recovery.** If a run stopped half way (for example you ended the box during a move), the review page
   and the vault show a bar with "Resume it" and "Roll it back".

Things worth checking: that the removed files and registry entries are gone inside the box, that undo puts
them back with the same content, and that the real machine (outside the box) did not change.

## Where things are inside the box

Paths below are for a box named `PurgeTest` and the default box root.

- Store (quarantine, journals, sessions):
  `C:\Sandbox\<user>\PurgeTest\user\current\AppData\Local\PurgeSandboxDev\`
  - `sessions\index.json` lists the sessions; each session folder has its `report.json`.
  - The quarantined files and the journals are next to it in the same store.
- The app's work folder (fingerprints, plans, selections, reports of each run):
  `C:\Sandbox\<user>\PurgeTest\user\current\AppData\Local\PurgeSandboxDevWork\`
- Files the test program wrote under `C:\` are under `C:\Sandbox\<user>\PurgeTest\drive\C\`.

To start again from nothing, end all programs in the box and delete its contents in Sandboxie-Plus.

## Known limits

- Only the main path is connected to the engine: Programs, Uninstall (quiet only), the leftover review,
  the move to quarantine, the vault with Undo, and Resume or Roll back. Home, Queue, History, Footprint,
  Assistant and Startup show sample data and say so at the top.
- Program sizes and space forecasts are not measured; they show as empty.
- The app runs each engine call as a child process inside a job object that ends with the app. Closing
  the window ends a running scan or move at once (a move then needs Resume or Roll back on the next start).
- "Delete for good" in the vault is not available in this build.
- There is no restore point and no consent dialog from the engine; the app's own confirmation is the only
  one.
- Uninstall runs the uninstaller quietly. A program without a quiet mode fails that step; use
  "Force remove" for it instead.
- The scan reads the real machine through the box. Leftovers of programs that are installed on the real
  machine may appear too. Moving them only changes the box's copy, but do not rely on that: test with a
  program that exists only in the box.

## Not verified yet (Sandboxie risks)

The engine was built and tested for a real Windows file system and registry. Sandboxie changes both under
the program. These points have not been tried inside a box yet and may fail or behave differently:

- **File ids.** The engine records file ids to tell that a file is still the same file. For a file that
  Sandboxie copies into the box on first write, the id changes between the scan and the move.
- **Handle-relative opens.** The engine opens files relative to an open folder handle. Sandboxie's
  redirection of such opens is not tested.
- **Final-path checks.** The engine checks the final path of an open handle against the expected path.
  Inside a box the final path may be the box path (`C:\Sandbox\...`), so the check may refuse the item.
- **Registry virtualisation.** Keys and values are read from the real registry merged with `RegHive`.
  Deleting a key that exists only in the real registry, and restoring it on undo, are not tested.
- **Quarantine renames across redirected paths.** The move to quarantine is a rename on the same volume.
  When the source is a real-machine path and the store is in the box, the rename may become a copy or
  fail.
- **Job objects for the uninstaller.** The app puts the engine in a kill-on-close job, and the engine runs
  the uninstaller in a job object of its own so it can wait for all its child processes. Sandboxie also
  puts sandboxed processes in its own job; these nested jobs and the wait for children are not tested.

If one of these fails, the engine should stop with a clear error and a journal you can roll back. Please
note what happened and keep the box's store folder.
