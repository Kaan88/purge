# install

`install.ps1` is the v1 deploy script (ENGINE_PLAN.md §3.2, §7.4, §7.9). It copies the engine to
`%ProgramFiles%\Purge` and creates `C:\ProgramData\Purge` with protected DACLs, so the broker never
works in a directory that a standard user could have pre-created or planted a junction in. A real
installer is an M7 item.

This file is the **single documented source of the SDDL constants**. `purge-exec` storage checks
(M2-X-STORE) and the VM gate compare against the strings in the table below, verbatim.

## Usage

Windows PowerShell 5.1, 64-bit, elevated:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 [-Engine <purge-engine.exe>] [-Kb <dir>] [-ReportPath <json>]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Check     [-ReportPath <json>]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File install\install.ps1 -Uninstall [-ReportPath <json>]
```

| Parameter | Default | Meaning |
|---|---|---|
| `-Engine` | `<repo>\target\release\purge-engine.exe` | Engine to deploy; the file must be named `purge-engine.exe`. |
| `-Kb` | `<engine dir>\kb` if it exists, else `<repo>\kb` | Knowledge files copied to `%ProgramFiles%\Purge\kb` (the engine reads `<exe dir>\kb`). |
| `-ProgramFilesDir`, `-DataRoot` | `%ProgramFiles%\Purge`, `%ProgramData%\Purge` | Test overrides only (absolute drive paths). |
| `-Check` | | Verify both trees, change nothing. Exit 0 only when both are exactly as installed. |
| `-Uninstall` | | Remove `%ProgramFiles%\Purge` only. The data root is never touched. |
| `-ReportPath` | | Write a `purge.install/1` JSON report (actions, renamed-aside trees with reasons, final SDDLs, log). |

Exit code: 0 on success (including "nothing to do" and "something was renamed aside"; the report and the
log say so), 1 on any failure (not elevated, 32-bit host, a rename or create failed, the tree did not
verify after the bounded passes). Every line of output starts with `install:`.

The script never downloads anything, never changes Defender or System Restore settings, and signs
nothing (signing stays out of M2, decision Q7).

## Release build

A release is two separate builds, run from the repository root, then the dependency check:

```
cargo build --release -p purge-engine
cargo build --release -p purge-broker
cargo xtask check-deps
```

- Two commands, never one. `cargo build -p purge-engine -p purge-broker`, `--workspace` and
  `--all-features` unify features across everything they build, so `purge-engine.exe` would get
  purge-win's `write` (the broker's) and any feature another member switches on. Built on its own, the
  engine links no executor and has no `write` (check-deps rule 4c).
- No `--features`. The engine's `rig-exec` and `inject-view` are for the VM rig and for tests; the
  broker has no feature at all (rule 4b).
- No `RUSTFLAGS` in the environment. It replaces the `crt-static` flags of `.cargo/config.toml`, and a
  `--cfg feature="..."` in it would switch on feature-gated code that no dependency tree shows.
- `purge-broker.exe` is the only release binary that links the executor (`purge-exec`); it links the
  engine's library with the release engine's features. The second build compiles only that library, so
  the `purge-engine.exe` of the first build stays as it was.
- `cargo xtask check-deps` checks the trees these two commands build (rule 4 in
  `tools/xtask/src/check_deps.rs`). Do not ship a build that fails it.

`-Engine` takes the `purge-engine.exe` of the first build. Deploying `purge-broker.exe` beside it comes
with the M3 `install.ps1` additions.

## Layout

```
%ProgramFiles%\Purge\            ProgramFiles   engine + kb\ (files inherit the root's DACL)
%ProgramData%\Purge\             DataRoot
    sessions\                    Sessions       one directory per session (created by purge-exec)
        index.json               Index          created as the 2-byte document {} (UTF-8, no BOM)
    Quarantine\                  Store          same-volume quarantine (purge-exec creates <session>\<op>)
    fp\                          Store          fingerprints
    kb\                          Store          writable knowledge (learned packs; empty in M2)
```

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
already matches are left alone (report `changed: false`). Payload files present in Program Files but no
longer in the source are reported as stale and left in place.

`-Uninstall` removes `%ProgramFiles%\Purge` (refusing if it is a reparse point or a file) with a walk that
removes links as links and never enters them. It never touches the data root.

## For purge-exec (M2-X-STORE)

- Directories that purge-exec creates under `sessions` and `Quarantine` should use the `Store` constant
  (inheritable admin-only, no Users ACE); `X:\.purge-q` likewise.
- The atomic rewrite of `index.json` (temp file + rename inside `sessions`) must give the temp file the
  `Index` descriptor at creation, or Users lose read access (a new file in `sessions` inherits only the
  SYSTEM and Administrators ACEs).
- `index.json` starts as `{}`: the session-index reader must accept an empty object (all fields
  defaulted).

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

VM gate G0 (`-Mode m2-install`, run by the rig, elevated in the guest):
- fresh install: the canonical SDDL of `Purge`, `sessions`, `Quarantine`, `fp`, `kb`, `index.json` and
  `%ProgramFiles%\Purge` equals the constants; `install.ps1 -Check` exits 0; a second install reports
  `changed: false`;
- a medium-integrity user (LaunchMedium) pre-creates `C:\ProgramData\Purge`, or plants a junction at
  `Quarantine` or `sessions\<x>` before install: the report lists the tree under `renamed_aside`, the
  junction targets (canaries) are unchanged, and the new tree verifies;
- a medium-integrity user cannot create a file or a junction in any of the directories, cannot list
  `Purge` or `sessions`, and can read `sessions\index.json`.
