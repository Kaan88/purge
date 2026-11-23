# install

`install.ps1` is the v1 deploy script (ENGINE_PLAN.md §3.2, §7.4, §7.9; package M3-INSTALL). It builds
the release artifacts, copies `purge-engine.exe`, `purge-broker.exe`, the published UI (`Purge.exe` and
its WinUI files) and `kb\` to `%ProgramFiles%\Purge`, creates `C:\ProgramData\Purge` with protected
DACLs, registers the `Purge` event-log source and creates one all-users Start-menu shortcut. A real
installer is an M7 item.

This file is the **single documented source of the SDDL constants**. `purge-exec` storage checks
(M2-X-STORE) and the VM gate compare against the strings in the table below, verbatim.

## Usage

Windows PowerShell 5.1, 64-bit, elevated (except `-WhatIf`):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 [-Engine <exe>] [-Broker <exe>] [-UiPublishDir <dir>] [-Kb <dir>] [-SkipBuild] [-ReportPath <json>]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -WhatIf     [-ReportPath <json>]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Check      [-ReportPath <json>]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Uninstall  [-ReportPath <json>]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -EngineOnly [-Engine <exe>] [-Kb <dir>]   # legacy M1b/M2 rig mode
```

| Parameter | Default | Meaning |
|---|---|---|
| `-Engine` | `<repo>\target\release\purge-engine.exe` | Engine to deploy; the file must be named `purge-engine.exe` and carry no executor marker. |
| `-Broker` | `<repo>\target\release\purge-broker.exe` | Broker to deploy; the file must be named `purge-broker.exe`. |
| `-UiPublishDir` | `<repo>\target\ui-publish` | The AOT publish folder; it must contain `Purge.exe`. |
| `-Kb` | `<engine dir>\kb` if it exists, else `<repo>\kb` | Knowledge files copied to `%ProgramFiles%\Purge\kb` (the broker and the engine read `<exe dir>\kb`). |
| `-SkipBuild` | | Deploy the artifacts as they are; run neither `cargo` nor `dotnet`. |
| `-DataRootOnly` | | Inno Setup mode (install only): the setup copied the payload already. Create the data root and the event-log source; no build, no payload copy, no shortcut. |
| `-ProtectOnly` | | Inno Setup mode (install only): set the payload's root, and every object in it that fails the broker's per-object rule, to the `ProgramFiles` descriptor (owner Administrators, protected DACL). |
| `-EngineOnly` | | Legacy M1b/M2 rig mode: deploy `purge-engine.exe` and `kb\` plus the data root only; no broker, UI, event-log source or shortcut, and no build. `-Check` and `-Uninstall` honour it. |
| `-ProgramFilesDir`, `-DataRoot`, `-StartMenuDir` | `%ProgramFiles%\Purge`, `%ProgramData%\Purge`, the all-users Start-menu `Programs` folder | Test overrides only (absolute drive paths). |
| `-WhatIf` (alias `-DryRun`) | | Print every step and change nothing. Needs no elevation; exit 0 when the plan is valid. |
| `-Check` | | Verify both trees, every deployed file, the shortcut and the event-log source; change nothing. Exit 0 only when everything is exactly as installed. |
| `-Uninstall` | | Remove `%ProgramFiles%\Purge`, the shortcut and the event-log source. The data root is never touched. |
| `-ReportPath` | | Write a `purge.install/1` JSON report (actions, renamed-aside trees with reasons, final SDDLs, checks, log). |

Exit code: 0 on success (including "nothing to do" and "something was renamed aside"; the report and the
log say so), 1 on any failure (not elevated, 32-bit host, an artifact missing, an install directory off the
system volume, a rename or create failed, the tree did not verify after the bounded passes). Every line of
output starts with `install:`.

The script never downloads anything, never changes Defender or System Restore settings, and signs
nothing (signing stays out of M2, decision Q7). It creates no service, task, run value or uninstall (ARP)
entry; the `Purge` Application event-log source is the one registry key M3-HARDEN requires.

## Release build

A release is two separate Rust builds, the dependency check, then the UI publish:

```
cargo build --release -p purge-engine
cargo build --release -p purge-broker
cargo xtask check-deps
dotnet publish ui\Purge.App -c Release -r win-x64 -o target\ui-publish
```

- Two commands, never one. `cargo build -p purge-engine -p purge-broker`, `--workspace` and
  `--all-features` unify features across everything they build, so `purge-engine.exe` would get
  purge-win's `write` (the broker's) and any feature another member switches on. Built on its own, the
  engine links no executor and has no `write` (check-deps rule 4c).
- No `--features`. The engine's `rig-exec` and `inject-view` are for the VM rig and for tests; the
  broker has no feature at all (rule 4b).
- No `RUSTFLAGS` in the environment. It replaces the `crt-static` flags of `.cargo/config.toml`, and a
  `--cfg feature="..."` in it would switch on feature-gated code that no dependency tree shows. The
  script refuses to build when `RUSTFLAGS` is set.
- `purge-broker.exe` is the only release binary that links the executor (`purge-exec`); it links the
  engine's library with the release engine's features. The second build compiles only that library, so
  the `purge-engine.exe` of the first build stays as it was.
- `cargo xtask check-deps` checks the trees these two commands build (rule 4 in
  `tools/xtask/src/check_deps.rs`). Do not ship a build that fails it.
- The UI publish is Native AOT and self-contained (`ui/Purge.App/Purge.App.csproj`); it needs the .NET 10
  SDK and the Visual Studio C++ desktop workload. The script looks for `dotnet` on `PATH`, then in
  `C:\Program Files\dotnet`.

Before deploying, the script reads `purge-engine.exe` and refuses a binary that carries a `purge-exec`
panic-location marker (`purge-exec\src` or `purge-exec/src`): such an engine was built with `rig-exec`.
`-SkipBuild` skips only the build, not that check.

## Layout

```
%ProgramFiles%\Purge\            ProgramFiles   purge-engine.exe, purge-broker.exe, Purge.exe and its
                                                WinUI files, kb\ (every object admin-only writable)
%ProgramData%\Purge\             DataRoot
    sessions\                    Sessions       one directory per session (created by purge-exec)
        index.json               Index          created as the 2-byte document {} (UTF-8, no BOM)
        writer.lock              (store file)   created by purge-exec on first use; the single-writer lock, held open
    Quarantine\                  Store          same-volume quarantine (purge-exec creates <session>\<op>)
    fp\                          Store          the broker's fingerprints (checked by purge-exec on every use, like Quarantine)
        msitables\               Store          the broker's MSI table cache (created and checked by purge-exec on first use)
    baseline\                    Store          the local baseline cache (created and checked by purge-exec on first use)
    kb\                          Store          writable knowledge (learned packs; empty in M2)
%ProgramData%\Microsoft\Windows\Start Menu\Programs\Purge.lnk
                                                one all-users shortcut to %ProgramFiles%\Purge\Purge.exe
HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Purge
                                                the "Purge" Application event-log source
```

`Purge.exe` finds `purge-broker.exe` beside itself (`BrokerLauncher.PathBesideApp`) and
`purge-engine.exe` beside itself (or the file named by `PURGE_ENGINE`, a development switch).

## The broker's start checks and what satisfies them

`bins/purge-broker/src/start.rs` refuses to start (exit 21 `install_untrusted`, 22 `store_integrity`,
20 `not_elevated`) unless all of the following hold. The right column is the install step that makes it
true; the left column names the code rule.

| Check (start.rs) | Satisfied by |
|---|---|
| `restrict_dll_search` | the broker's own first call; nothing to install |
| token elevated | the UI's `runas`; the installer itself is elevated |
| own directory: plain drive path, no reparse point on any component, final path equal, on the system volume, admin-only writable (`trusted_install_dir`) | `Assert-SystemVolume` refuses an install directory off the Windows volume; `Install-Tree` creates `%ProgramFiles%\Purge` with the `ProgramFiles` descriptor in the creating call and rejects/recreates any tree with a reparse point at its top two levels |
| the running executable (`purge-broker.exe`) admin-only writable | `Copy-Payload` copies it into the protected root, so it inherits the `ProgramFiles` descriptor, and the protection pass applies that descriptor itself to any object that fails the broker's rule |
| `<install dir>\kb` passes the directory rule | `Copy-FileTree` creates `kb\` below the protected root; the protection pass judges it by the same rule; `Install-Tree` refuses a reparse-point `kb` |
| `<install dir>\Purge.exe` (the client image) admin-only writable | the UI publish folder is copied into the protected root by `Copy-FileTree`; the protection pass covers `Purge.exe` itself |
| every file directly in `<install dir>\kb\baselines` admin-only writable | the protection pass visits every file of the deployed tree, `kb\baselines\*.tsv.gz` included |
| data root `%ProgramData%\Purge` passes the directory rule and `StorageRoots::check` (data root, `sessions`, `Quarantine`, `fp`) | `Install-Tree` creates the data layout (root, `sessions`, `Quarantine`, `fp`, `kb`, `sessions\index.json`) with its own protected descriptors |
| KB and baselines are `<install dir>\kb`, `PURGE_KB_DIR` is not read | the layout above; the engine and broker use `<exe dir>\kb` |

`fp`, `fp\msitables` and `baseline` are checked store directories (DECISIONS 2026-11-22, "fp checked"
and "baseline checked"): the broker reaches every file in them relative to the handle they were checked
through, never by path, and one that is a reparse point or that anyone but Administrators and SYSTEM may
write is renamed aside to `<name>.rejected-<utc>` and replaced. A `msitables` or `baseline` an older
broker or engine created by path (inherited, unprotected DACL) is renamed aside once that way and its
cache rebuilt (the local baseline in the background, minutes). An `fp` an older broker created that way
is renamed aside too, but its fingerprints (`fp-<sha256>.json`, admin-owned plain files) are moved into
the new `fp` at once and the broker starts normally. The broker removes what these directories renamed
aside after 30 days.

`-Check` re-runs both tree verdicts, the deployed-file rule, the shortcut target and the event-log source,
so it fails when any row above would fail after the fact (a replaced binary, a `Users` write ACE added to
a baseline, a deleted file).

## SDDL constants

Owner and DACL only (group and SACL are not part of the contract). All ACEs are explicit; every DACL is
protected, so nothing is inherited from `C:\ProgramData` (whose inherited ACEs let Users create folders)
or `C:\Program Files`.

| Constant | Applies to | SDDL |
|---|---|---|
| `DataRoot` | `C:\ProgramData\Purge` | `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100020;;;BU)` |
| `Sessions` | `C:\ProgramData\Purge\sessions` | `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x100020;;;BU)` |
| `Store` | `Quarantine`, `fp`, `kb` under `C:\ProgramData\Purge` | `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` |
| `Index` | `C:\ProgramData\Purge\sessions\index.json` | `O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)` |
| `ProgramFiles` | `C:\Program Files\Purge` | `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)` |

Rights: `FA` = FILE_ALL_ACCESS (0x1f01ff); `FR` = FILE_GENERIC_READ (0x120089: read data, EA and
attributes, READ_CONTROL, SYNCHRONIZE); `0x1200a9` = read and execute; `0x100020` = FILE_TRAVERSE |
SYNCHRONIZE.

**Comparison rule.** Render both the object's security descriptor and the constant with
`ConvertSecurityDescriptorToStringSecurityDescriptorW(OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)`
(the constant after `ConvertStringSecurityDescriptorToSecurityDescriptorW`), then reduce the `D:` control
flags to `P` (or `NO_ACCESS_CONTROL`): `AI` and `AR` are auto-inheritance bookkeeping that
`CreateDirectoryW`, `SetSecurityInfo` and other tools may or may not set, and they grant nothing. The
strings must then be equal. The constants above are already in that canonical form (the self-test checks
it), so `D:PAI(...)` on disk equals `D:P(...)` here.

**Why these ACEs.**
- SYSTEM and Administrators get full control, inheritable (`OICI`) so that what `purge-exec` creates
  below (session dirs, journals, quarantined items) is admin-only too. purge-exec still creates its own
  directories with an explicit descriptor and checks them on every use (§7.4).
- Users get nothing that writes, anywhere: no file or junction can be created by a medium-integrity
  process (an elevated admin's filtered token holds Administrators as deny-only, so it is a plain User).
- `index.json` is the one object Users can read (decision Q7: the UI reads it after first paint for
  "N items expire soon"). `FR` allows opening and reading it, nothing else.
- To open `index.json` by full path a user needs traverse on `Purge` and `sessions`. These two
  directories carry a **traverse-only**, non-inherited ACE for Users: FILE_TRAVERSE plus SYNCHRONIZE,
  with no FILE_LIST_DIRECTORY and no FILE_READ_ATTRIBUTES, so Users can neither list nor stat them, and
  the ACE does not reach session subdirectories. (With the default "Bypass traverse checking" right,
  SeChangeNotifyPrivilege, held by Everyone, traverse is not even checked; the ACE keeps the read
  working on hosts where that right was removed.) SYNCHRONIZE is in the mask because 0x20 alone renders
  as the directory-service token `WP`, which reads like a write right.
- `%ProgramFiles%\Purge` is admin-only for writing; Users can read and execute (they start the engine
  and, from M3, the UI). The DACL is protected so `CREATOR OWNER` and other inherited Program Files
  ACEs do not apply.

## Integrity check and rename-aside

Each object is created with its descriptor **in the creating call** (`CreateDirectoryW` /
`CreateFileW(CREATE_NEW)` with `SECURITY_ATTRIBUTES`), which fails if anything already exists at the
path, so there is no window in which the inherited ProgramData ACEs apply and no way to adopt an object
a user created first.

An existing tree (Program Files or data root) is checked through handles opened with
`FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` (the object itself, never a link target):

1. the root: exists as a directory, is not a reparse point, owner `BUILTIN\Administrators`, protected
   DACL, canonical SDDL equal to its constant;
2. only if the root passes: every layout object present passes the same check against its constant, and
   no entry at the top two levels (`Purge\*`, `Purge\*\*`) is a reparse point. Directory entries are
   read without descending into any reparse point.

Verdicts: **good** (nothing to do), **incomplete** (only layout objects are missing: create them),
**absent** (create everything), **reject** (anything else). A rejected tree is never adopted and never
recursed into: its root is renamed to `<name>.rejected-<yyyyMMddTHHmmssZ>` (suffix `-2`, `-3`... if taken)
in the same folder through `SetFileInformationByHandle(FileRenameInfo)` on a handle opened with
`FILE_FLAG_OPEN_REPARSE_POINT` (a junction is renamed as a link, its target is untouched), the reasons
are logged and reported, and a fresh tree is created. Nothing is ever deleted, so quarantined items in a
rejected data root stay recoverable by hand. The loop is bounded (4 passes): a user who keeps
re-creating `C:\ProgramData\Purge` makes the run fail, never adopt.

Rejection reasons reported per object: reparse point, wrong kind (file vs directory), security
descriptor unreadable, owner not Administrators, null or unprotected DACL, write-class rights (write or
append data, add file or subdirectory, write EA or attributes, delete, delete child, WRITE_DAC,
WRITE_OWNER, GENERIC_WRITE or GENERIC_ALL) for any principal other than SYSTEM, Administrators or
TrustedInstaller (inherit-only ACEs included), and finally any difference from the constant. Even a
difference that grants nothing (an extra Users list ACE, a SYSTEM owner) rejects the tree: install only
adopts exactly what it creates.

Idempotence: on a good tree nothing is created, renamed or rewritten; payload files whose SHA-256
already matches are left alone and a deployed object that already passes the broker's per-object rule is
not touched (report `changed: false`). Payload files present in Program Files but no longer in the source
are reported as stale and left in place.

`-Uninstall` removes `%ProgramFiles%\Purge` (refusing if it is a reparse point or a file) with a walk that
removes links as links and never enters them, removes the Start-menu shortcut and removes the `Purge`
event-log source. It never touches the data root.

## Deployed files, shortcut and event-log source

`Copy-Payload` copies `purge-engine.exe`, `purge-broker.exe`, the whole UI publish folder (relative paths
kept, `Assets\` included) and `kb\` into the verified root. A file whose SHA-256 already matches is left
alone; an existing file is overwritten; a file in the destination that matches no source is reported as
`stale (left in place)` and never deleted.

New files inherit the root's protected descriptor, but a replaced file or one copied from another tree can
carry its own. The broker judges `purge-broker.exe`, `Purge.exe` and every file in `kb\baselines` one by
one (`is_admin_only_writable`), so after copying, the script walks the whole deployed tree and applies the
`ProgramFiles` constant (owner `Administrators`, protected DACL, Users read and execute) to any object
that fails that rule. A reparse point anywhere in the deployed tree is refused, not followed. This is why
an installed layout passes the broker's start check even when the source tree had other permissions.

The shortcut is `Purge.lnk` in the all-users Start-menu `Programs` folder, target
`%ProgramFiles%\Purge\Purge.exe`, working directory the install folder, icon from the same file. An
existing shortcut with that target is left alone; `-Uninstall` removes it.

The `Purge` Application event-log source is registered as
`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Purge`. The key alone is the registration:
the broker passes its failure line as the event's text (`purge-win::eventlog`), so no message DLL is
needed. The event id is the broker's exit code (20, 21, 22 for start failures; 23-27 and non-zero for
other exits).

`-WhatIf` (`-DryRun`) prints every step - the two cargo builds, the dependency check, the UI publish, the
payload and data-tree installs, the protection pass, the event-log source and the shortcut - and returns 0
without elevation or a single write.

## Inno installer

`install/inno/purge.iss` is the setup the v1 deploy script is not: one `Purge-Setup-<version>.exe` that
installs, upgrades and uninstalls from one file, with an "Installed apps" entry. It needs Inno Setup 6.3
or newer (built here with 6.7.3) and does not replace the script; it runs the script's protected-tree
logic from its post-install step.

```
winget install --id JRSoftware.InnoSetup -e
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\inno\build-installer.ps1 [-SkipBuild] [-InnoCompiler <ISCC.exe>]
```

The script builds what "Release build" above describes (`cargo` twice, `cargo xtask check-deps`, the
Native AOT publish), then compiles the setup into `target\installer\Purge-Setup-<version>.exe`, the
version taken from `[workspace.package] version` in the root `Cargo.toml`. `-SkipBuild` packs the
artifacts that already exist. Build-time only: no elevation and no change to the machine.

**Install.** The setup is x64, `PrivilegesRequired=admin`, `DefaultDirName={autopf}\Purge` and
`DisableDirPage=yes`: the broker refuses a directory a non-administrator can write, so the user cannot
pick another one. `[Files]` copies `purge-engine.exe`, `purge-broker.exe`, the whole UI publish folder
(`Purge.exe` and its Windows App SDK files) and `kb\` into `{app}` (`= %ProgramFiles%\Purge`), plus
`install.ps1` into `{app}\setup\`. `[Icons]` creates the same all-users Start-menu shortcut the script
does (`{commonprograms}\Purge`, i.e. `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Purge.lnk`)
and an optional desktop shortcut (unchecked task). `AppId` is a fixed GUID, so a second setup upgrades
the same "Installed apps" entry; name, version and publisher ("Purge") come from `AppName`,
`AppVersion` and `AppPublisher`.

| Check (`bins/purge-broker/src/start.rs`) | What the setup does for it |
|---|---|
| `restrict_dll_search` | the broker's own first call; nothing to install |
| token elevated | `PrivilegesRequired=admin` (the setup itself); the UI starts the broker with `runas` |
| own directory: plain drive path, no reparse point, system volume, admin-only writable (`trusted_install_dir`) | `DefaultDirName={autopf}\Purge` + `DisableDirPage=yes` fixes `%ProgramFiles%\Purge`; Inno creates plain directories; `-ProtectOnly` applies the `ProgramFiles` constant |
| `purge-broker.exe` admin-only writable | Inno's copy inherits Program Files (Users: read and execute), which the rule accepts; `-ProtectOnly` repairs it when the copied file's own descriptor fails |
| `<install dir>\kb` passes the directory rule | `kb\` is copied below the protected root; `-ProtectOnly` visits the directory too |
| `<install dir>\Purge.exe` admin-only writable | the UI publish tree goes into `{app}`; `-ProtectOnly` visits `Purge.exe` |
| every file in `<install dir>\kb\baselines` admin-only writable | `kb\baselines\*` is copied by the same rule; `-ProtectOnly` walks every file of the tree |
| data root `%ProgramData%\Purge` passes the directory rule and `StorageRoots::check` | `install.ps1 -DataRootOnly` creates `Purge`, `sessions`, `Quarantine`, `fp`, `kb` and `sessions\index.json` with the `DataRoot`, `Sessions`, `Store` and `Index` descriptors |
| KB and baselines are `<install dir>\kb`, `PURGE_KB_DIR` is not read | `DestDir: "{app}\kb"`; nothing sets `PURGE_KB_DIR` |

**Post-install.** In `[Code]` at `ssPostInstall` the setup runs, from `{app}\setup\install.ps1`:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File {app}\setup\install.ps1 -ProtectOnly -DataRootOnly -SkipBuild
powershell.exe -NoProfile -ExecutionPolicy Bypass -File {app}\setup\install.ps1 -Check
```

The first run gives the tree the layout's own descriptor. Inno's file copy inherits the Program Files
DACL, which already grants Users only read and execute, but that is not the protected `ProgramFiles`
constant, so `-ProtectOnly` sets the root to the constant itself and applies it to every object below
it that fails the broker's per-object rule. The same run creates `%ProgramData%\Purge` with its
protected descriptors and `sessions\index.json`, and registers the `Purge` event-log source, all through
the script's native layer: the .iss adds no `Permissions:` entry and no SDDL of its own. The second run
is the script's own `-Check` (both trees, every deployed file, the shortcut, the event-log source). If
either run fails, the setup shows the end of the script's log (a silent setup only writes it to the
setup log) and exits with code 9 instead of 0 (`GetCustomSetupExitCode`), so Hub records a failed
update. There is no rollback: Inno has already copied the files and written the uninstall entry with
the new `DisplayVersion` when `ssPostInstall` runs, and it cannot undo them from there (an `Abort` at
that point is swallowed and the setup still exits 0). An interactive run says so on the Finished page
and does not offer to launch Purge; running the setup again repeats the step. Hub does not offer it again (the new `Purge.exe` already carries the new version), so after an exit 9 the owner runs the setup by hand. `SetupLogging=yes`, so
the setup's own log is always `%TEMP%\Setup Log <date> #<n>.txt`, also for Hub's run, which passes
no `/LOG`.

**Uninstall.** From "Installed apps" (or `unins000.exe`). Before the uninstaller deletes any file,
`CurUninstallStepChanged(usUninstall)` force-stops `Purge.exe`, `purge-broker.exe` and
`purge-engine.exe` by image name (`taskkill /F /IM`, without `/T`, so a program's uninstaller the broker
started is left alone), removes
`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Purge`, then asks whether to delete
`%ProgramData%\Purge` too. The default is **No** (silent uninstalls keep it without asking): the quarantine holds
files that were removed from the PC and can still be restored, so deleting the folder is an explicit
choice. The answer is only about the data root; the programs, `kb\`, `setup\`, the shortcuts and the
registry source are always removed, and `[UninstallDelete]` clears `{app}` after that.

**Upgrade, and Hub.** Hub (`Kaan88/mdhub`, `docs/COMPLIANCE.md`) installs and updates Purge by running
the setup elevated with `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` and reading its exit code (0 is
success). A silent run shows nothing and asks nothing: the `[Run]` entry is `skipifsilent`, a failed
post-install step only writes to the setup log and exits with code 9, and there is no custom page. Hub asks Purge's window to
close and never ends a process, and the broker and the engine have no window, so `PrepareToInstall`
stops Purge itself:
- It refuses any install folder but `{autopf}\Purge` (exit code 7, nothing changed). There is no
  directory page, but `/DIR=` on the command line would still pick another folder, and the stop step,
  the re-protection of the tree and `[UninstallDelete]` all act on `{app}`.
- It stops only the app's own executables in that folder: a process whose path is exactly
  `{app}\Purge.exe`, `purge-broker.exe`, `purge-engine.exe` or `RestartAgent.exe` (the Windows App SDK
  helper the UI publish ships), found through WMI; Purge.exe first; `taskkill /F /PID`, no `/T`, so a
  program's uninstaller the broker started is left alone. It waits up to 10 s until they are gone and
  their files can be opened for writing.
- Without WMI it opens the four files instead: for each of the three Purge images whose installed file
  is in use it runs `taskkill /F /IM` (no `/T`; never for `RestartAgent.exe`, which every Windows App
  SDK app has), then waits up to 10 s for the files to be free.
- If a file of the app is still in use after that, the setup stops before it changes anything (exit
  code 7, "Purge could not be closed"). Run interactively, it asks before it stops anything. A
  `/VERYSILENT` run without `/SUPPRESSMSGBOXES` shows Inno's error box first; Hub passes both.

`CloseApplications=yes` stays as the fallback for anything else holding a file. `AppId` and `DefaultDirName` never change, and the
`DisplayVersion` Inno writes is `AppVersion`.

**Version.** The one version is `[workspace.package] version` in the root `Cargo.toml`.
`build-installer.ps1` passes it as `/DAppVersion` (`purge.iss` has no default), the engine's and the
broker's `VERSIONINFO` come from it (`bins/versioninfo.rs`, included by both `build.rs`), and
`ui/Directory.Build.props` reads it from `Cargo.toml` for `Purge.exe` (`Version`, `FileVersion`,
`InformationalVersion`). `install/inno/check-version.ps1` checks `Cargo.lock`, the three exes
(`ProductVersion` = the version, fixed `FILEVERSION` = `X.Y.Z.0`) and the setup; the preprocessor of
`purge.iss` refuses the same mismatches. `.github/workflows/release.yml` builds, checks and publishes
a release for the tag `v<version>`, with the `hub.txt` Hub reads.

The setup must be tested on the target machine, elevated: it writes Program Files, ProgramData and
HKLM, which is exactly what cannot be verified by compiling it. Its first VM run checks, each with
`/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` and the exit code: exit 0 on a fresh install and on an idle
upgrade over an existing data root (`-ProtectOnly -DataRootOnly` and `-Check` pass); the kill of a
running elevated broker and the journal recovery after it; exit 7 when a process survives; exit 7 for
`/DIR=` another folder, nothing changed; exit 9 when the post-install step fails (for example a
`-Check` made to fail), with the reason in the setup log.

## For purge-exec (M2-X-STORE)

- Directories that purge-exec creates under `sessions` and `Quarantine` should use the `Store` constant
  (inheritable admin-only, no Users ACE); `X:\.purge-q` likewise.
- The atomic rewrite of `index.json` (temp file + rename inside `sessions`) must give the temp file the
  `Index` descriptor at creation, or Users lose read access (a new file in `sessions` inherits only the
  SYSTEM and Administrators ACEs).
- `index.json` starts as `{}`: the session-index reader must accept an empty object (all fields
  defaulted).
- `sessions\writer.lock` is created by purge-exec, not by the setup, with the admin-only store file
  descriptor. Every writing operation holds it open with no sharing; the setup and uninstall need not
  know it (a leftover file locks nothing).

## Tests

Host (no elevation, no VM, writes only to `%TEMP%`):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\tests\install-selftest.ps1
```

It parses the scripts, checks that the constants in this file equal the builder's output and are in
canonical form, runs the integrity verdict over fake facts (pre-created user tree, unprotected DACL,
reparse root, planted junction at level 1 and 2, extra ACEs, Users write ACE, unreadable descriptor,
`D:PAI` variant), drives the install loop over a fake file system (reject -> rename aside -> create ->
good, second run a no-op, an attacker re-creating the root every pass), and exercises the native layer in
a temp folder: create-with-descriptor round trip, `CREATE_NEW` refusal, reparse detection, handle-based
rename of a junction (target untouched) and the non-following tree removal.

The M3 rows add, in a temp folder and with a descriptor owned by the test user: a fresh payload copy of
engine, broker, a UI publish tree and `kb` (including a subdirectory), a re-run that reports every file
`unchanged` and `changed: false`, one changed source file reported `updated`, a stale file reported and
left in place, the per-object protection rule (a file given an `Everyone` write ACE is named by `-Check`
and re-protected by the next run), the shortcut create/verify/remove round trip, `Test-PayloadLayout`
over the payload, the executor-marker check on a fake binary (clean, and a `purge-exec\src` marker
refused), and the entry point's `-WhatIf` plan for install, check and uninstall (exit 0, no elevation,
nothing written) plus the non-elevated real run (exit 1, "run elevated"). The Inno setup mode adds one
row: `-ProtectOnly -DataRootOnly -WhatIf` must name the tree protection and the data root, and no build.

VM gate G0 (`-Mode m2-install`, run by the rig, elevated in the guest):
- fresh install: the canonical SDDL of `Purge`, `sessions`, `Quarantine`, `fp`, `kb`, `index.json` and
  `%ProgramFiles%\Purge` equals the constants; every file of the payload passes
  `is_admin_only_writable`; the `Purge` event-log source and the Start-menu shortcut exist;
  `install.ps1 -Check` exits 0; a second install reports `changed: false`;
- a medium-integrity user (LaunchMedium) pre-creates `C:\ProgramData\Purge`, or plants a junction at
  `Quarantine` or `sessions\<x>` before install: the report lists the tree under `renamed_aside`, the
  junction targets (canaries) are unchanged, and the new tree verifies;
- a medium-integrity user cannot create a file or a junction in any of the directories, cannot list
  `Purge` or `sessions`, and can read `sessions\index.json`;
- the installed `purge-broker.exe`, started with `--pipe`/`--parent`, passes its start checks (the
  layout and DACLs above are exactly what `bins/purge-broker/src/start.rs` accepts), and `-Uninstall`
  removes the Program Files tree, the shortcut and the source, leaving the data root.

### Release stage
`install/release-stage.txt` holds one lower-case word, the stage the release workflow puts in the release title
("Purge 0.1.2 (alpha)"): `alpha` now, `beta` when the beta starts, and an empty file for final releases. The
version itself stays `X.Y.Z` (Hub's `releases/latest` skips pre-releases, so a `-beta` version would never reach it).
