# M3-R1 review: wave 2 (M3-RPC, M3-DEPS, M3-WIN-PIPE, M3-WIN-PRIV, M3-WIN-TASKDLG, M3-HARDEN)

Date 2026-11-21. Reviewer: Fable. Branch `baseline`, HEAD 5201102, diff `02f8830..baseline`.
Read-only review; no code changed, nothing built, no test, no xtask and no VM run. Two read-only host commands
besides git: a string scan of an existing `target\debug\purge-broker.exe` for import names (finding M1) and a
listing of the crates' `[features]` tables.

Inputs: `docs/M3_DESIGN.json` (`review_points` M3-R1), `docs/M3_DESIGN.md` 3.3 to 3.6 and section 4 (T1 to T16),
`docs/m3-notes/wave2-writers.md`, `docs/DECISIONS.md` (2026-11-21 rows), and in full or as diff:
`purge-win` `pipe.rs`, `token.rs`, `privilege.rs`, `process.rs` (diff), `reg_write.rs` (diff, `CreatedKey`),
`secure.rs`, `known_folders.rs` (diff), `eventlog.rs`, `taskdialog.rs` (production part), `sid.rs`
(`is_admin_only_writable`); `bins/purge-broker` `start.rs`, `main.rs`, `build.rs`, the manifest, `Cargo.toml`;
`bins/purge-engine` `main.rs`, `pipeline.rs`, `pipeline/baseline.rs` (diffs); `purge-exec` `act_service.rs`
(`set_recorded_security` and what it calls); `purge-rpc` `sets.rs`, `table.rs`, `frame.rs`, `methods.rs` (ids,
params, call sets), the shape walk of `lib.rs`; `tools/xtask/src/check_deps.rs` (rules 1 to 4f, production part);
`purge-model` `ids.rs`, `exec/session.rs`; `purge-scan` `framework.rs` (`candidate_id`); `purge-plan`
`decide.rs` (`merge`).

Not read: the test modules beyond the ones cited, `purge-rpc` result types, the UI tree, `purge-win`
`fs_write.rs`. Nothing below was confirmed by running it; where a claim rests on Windows behaviour I know from
reading and not from a run here, it says so.

Labels: B blocker, M must be fixed before the `m3-broker` gate (or before the package named), S should be fixed,
N note.

## Verdict

- **No B finding.** No Execute or Propose method is reachable over stdio; no broker request field carries a path
  or a document; the broker's start checks refuse every planted or foreign directory I could spell; the privilege
  is on for one closure on one thread and every exit path reverts; a second client and a squatter get nothing.
- **Two M findings**: the load flag the DECISIONS row records is not in the tree (M1), and the wire's candidate id
  is a 64-bit FNV-1a hash with no uniqueness rule, used as the selection key (M2).
- Nine S findings, eleven notes.

Counts: B 0, M 2, S 9, N 11.

## Findings

### M1. `/DEPENDENTLOADFLAG:0x800` is recorded as done and is not in the broker's build script

`bins/purge-broker/build.rs:3-13` emits `/MANIFEST:EMBED`, `/MANIFESTINPUT` and `/MANIFESTUAC:NO`, nothing else.
The DECISIONS row for M3-HARDEN lists "6) `/DEPENDENTLOADFLAG:0x800` in the broker's build.rs" as a choice made,
and its reason says "the install-dir rule plus the load flag close the load-path cases". The writer note had it
under "needs an owner". The only place the flag appears in code is a test fixture string
(`tools/xtask/src/check_deps.rs:2513-2517`).

Failure: T6's VM row ("a user-writable copy of the install directory; a DLL next to the broker in that copy").
`restrict_dll_search` (`start.rs:194-196`, first call of `main`) runs after the loader has resolved the static
imports, and for those the application directory is searched first for every DLL that is not a KnownDLL. A copy
of `purge-broker.exe` in a user-writable directory with a planted import therefore runs the planted code elevated
before `check()` can refuse the directory.

Reach today: the existing debug stub imports only `kernel32`, `advapi32`, `ntdll` and an API set (string scan; the
binary may predate M3-HARDEN), all KnownDLLs, so nothing is plantable yet. M3-BROKER-CORE links the executor and
the pipeline (`msi.dll`, `version.dll`, `userenv.dll`, `crypt32.dll`, `wintrust.dll` and others are not
KnownDLLs), and from then on T6 fails as designed. While the binary is unsigned the attacker gains nothing over
starting an own executable through `runas`; the row's own trigger ("a certificate is obtained") is when it turns
into an elevation under Purge's name.

Fix: `println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");` in `build.rs` (same in the engine's, if an
elevated engine is meant to be covered), and a check in `xtask ci` or the rig that the built image's load config
carries `DependentLoadFlags = 0x800`. Until then amend the DECISIONS row (section "DECISIONS rows").

### M2. Candidate ids on the wire are FNV-1a, and nothing says they are unique in a scan

`crates/purge-rpc/src/methods.rs:162-183` makes `CandidateRef` (`c-<16 hex>`) the client's handle for
`plan.create {selected[]}` and `candidate.explain`, and design 3.6 has the UI re-apply ticks "by candidate id"
after a new broker's rescan. The id is `purge-scan` `framework.rs:1777-1814`: 64-bit FNV-1a over the folded
target. `purge-plan` merges by canonical target (`decide.rs:777-835`), not by id, so two different targets with
one id stay two candidates with one id.

Attack: FNV-1a is not collision resistant and second preimages are cheap (each step is invertible; a
meet-in-the-middle over a few free bytes of a file or key name is minutes of work). Whoever can create a name
inside a location the scan lists (a file in the program's leftover data folder, a value under its HKCU key; a
medium process, or content the user unpacked there) can give it the id of another candidate of the same scan.
Then a tick on row A is, on the wire, also a tick on B; after an idle exit the old tick on A is re-applied to
whatever carries that id in the new scan; `candidate.explain` may describe the other one. The consent dialog is
drawn from the bound plan, so B is on screen if it is an attention item, which bounds the damage; an item outside
the attention classes past the first 100 is not shown.

Fix (binding for M3-BROKER-CORE, before `plan.create` is wired): the broker refuses to serve a scan in which two
candidates share an id (`plan_refused`, or drops both to unselectable and reports them), and a selection that
names an id selects exactly one target. Better: the wire id is assigned per scan by the broker (ordinal or
random), and the stable hash is used only for carrying ticks across rescans, where a changed target under the
same id counts as "changed" and is not re-ticked. If the hash stays as the key, make it a truncated SHA-256.

### S1. The first read is before the peer check, with no timeout and a 4 MiB line

Binding in the DECISIONS row: "read the first request line, then `peer()`". `PipeOptions::default()` has
`read_timeout: None` (`pipe.rs:92-99`) and the pipe line limit is 4 MiB (`sets.rs:84`). A same-user medium
process that connects and writes nothing holds the only instance for as long as it likes: the UI sees
`ERROR_PIPE_BUSY` until its 10 s retry gives up, and the broker has parsed nothing but also refused nothing, so
the "three refused clients" count never moves.

Fix: identify before reading. The UI opens with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, and the module
doc says such a client "can be identified at once" (`pipe.rs:484-490`); then `ReadFirst` is itself a refusal and
no byte of an unidentified client is parsed. `peer_before_any_read` (`pipe.rs:1129-1141`) prints either outcome
and asserts neither: pin it on the VM first. If it does not hold, keep the order but give the first read a short
timeout (5 s) and a small cap (the hello line), and count a timeout as a refused client.

### S2. `RtlAcquirePrivilege` is not in the check-deps list

`tools/xtask/src/check_deps.rs:635-640` lists `AdjustTokenPrivileges`, `NtAdjustPrivilegesToken`,
`ZwAdjustPrivilegesToken`, `RtlAdjustPrivilege`. `ntdll!RtlAcquirePrivilege` enables privileges by number (18 for
restore) on an impersonation token or the process token, names no privilege string and no listed API, so rule 4e
does not see it. `reg_write.rs` already declares raw `ntdll` externs, so the pattern is at hand. Fix: add
`RtlAcquirePrivilege` and `RtlReleasePrivilege` to `PRIVILEGE_APIS`.

### S3. The test-item filter of rule 4e takes `not(any(.., test, ..))` for test code

`check_deps.rs:682-704` rewrites a line `#[cfg(all(...))]` to `#[cfg(test)]` when any comma-separated piece
trims to `test`. `#[cfg(all(not(any(miri, test, doc)), feature = "write"))]` splits into `not(any(miri`, ` test`,
` doc))`, …: the item is production code and is blanked as test code, so a privilege name or an adjusting API
below it is not scanned. Fix: split only at nesting depth 0 of the `all(` arguments (or refuse any `cfg` in
production sources that mentions `test` in a form other than `#[cfg(test)]` and `#[cfg(all(test, …))]`).

### S4. The broker goes on when `SetDefaultDllDirectories` fails

`start.rs:194-196` discards the result. The call does not fail on supported Windows, so making it a start failure
costs nothing and removes the one path on which the elevated process keeps the default search order. Same for
`taskdialog.rs:402-411`, which loads `comctl32.dll` by bare name and relies on the caller having restricted the
search: `LoadLibraryExW(.., LOAD_LIBRARY_SEARCH_SYSTEM32)` makes the module safe on its own (activation-context
redirection to v6 still applies to a bare name; from reading, to be confirmed with the manifest test on the VM).

### S5. `ProgramId` is not an id "of a fixed form", and the module says it is

`methods.rs:7-11` says a broker request holds only ids whose form is fixed "so a path does not even read as one".
`ProgramId` (`purge-model/src/ids.rs:134-154`) takes any key name without a backslash and any hive name without
`|`, `\`, `:`: `HKLM|64|C:/x`, `HKLM|64|..`, `HKU:.DEFAULT|64|x` and a name with an embedded NUL all parse, and
the shape walk passes it because its schema has some `pattern` (`lib.rs:1234-1242`, `:1261-1268`). No registry
path can be injected (no backslash), so this is not a hole in wave 2. Bindings for M3-BROKER-CORE and the
fingerprint store, to be written where the writer note has "own inventory only":

- a `ProgramId` from the wire is only ever compared for equality with ids of the broker's own inventory or its
  own stored-fingerprint index; it is never turned into a registry path, and never into a file name (a stored
  fingerprint's file name is a hash or an index entry, not the key name);
- an id whose hive is not `HKLM` or `HKU:<the checked account's SID>` is refused before any lookup (design 3.5).

Fix in this package: correct the module text, and refuse control characters (NUL included) in `ProgramId::build`.

### S6. No arming delay on the approving button

`taskdialog.rs:8` rules out a timer "so no timeout answer"; `:312-327` brings the dialog to the foreground with
its buttons live. T1 covers injected input. It does not cover the user's own click: the client chooses the moment
`plan.execute` shows the dialog and the dialog's position is predictable (no owner, centred), so a click the user
aims at something else can land on the primary button. The verification gate protects every plan with an
attention item, so the exposed case is a plan of preselected items only. Fix: keep the primary button disabled
for about a second after `TDN_CREATED` and `TDN_NAVIGATED` to the last page (`TDF_CALLBACK_TIMER`, enable on the
first `TDN_TIMER` past the delay); a timer that only enables a button is not a timeout answer. Binding for
M3-CONSENT either way: every plan that holds an item the scan did not preselect is gated.

### S7. Files the broker will read below its directory are not judged

`start.rs:226-231` checks the directory chain and the broker's own file. `kb_dir` (`:249`) and `<dir>\Purge.exe`
(the peer's expected image, design 3.3) are not looked at. A file moved into the directory keeps its descriptor,
which is why the baselines have a per-file rule (`pipeline/baseline.rs`, "who can write a file that was moved
into it"). Binding for M3-BROKER-CORE: every KB file the broker loads passes the same per-file admin-only check,
and `ExpectedPeer.image` is checked with `is_admin_only_writable` once at start (a user-writable `Purge.exe` makes
the image check mean nothing).

### S8. A release built in one cargo call is not caught

Rule 4 rests on "two builds, never `--workspace`" (`check_deps.rs:18-21`). `cargo build --release -p purge-engine
-p purge-broker` or a build at the workspace root unifies features: the engine gets `purge-win/write` compiled in
and the broker's engine library gets xtask's `inject-view`. `default_build_violations` looks only at purge-exec's
features. Nothing a standard user can reach, but the release is then not the one the rules describe. Fix: an
`xtask release` that runs the two builds, and `install.ps1` refusing binaries that did not come from it (or a
build-id check).

### S9. An elevated engine does not "follow the same rule"

The 2026-11-21 hardening row says "An elevated `purge-engine` follows the same rule" (start only from a trusted
directory). `bins/purge-engine/src/main.rs` (`settings`, `main`) never refuses to start: it withholds trust from
the baseline directory and the caches (`is_admin_only_writable` plus the volume rule), and it carries no load
flag (M1). That is the right behaviour for a read-only engine; the row should say so, so nobody later relies on
a refusal that does not exist.

### Notes

- **N1** `pipe.rs:172`: the SDDL names no owner, so the owner is the token's default: Administrators for an
  elevated token (holds for split tokens and UAC off; from reading). A medium process is then not the owner and
  has no implicit `WRITE_DAC`. The broker could assert it once: `sddl()` read back starts with `O:BA` or `O:SY`.
- **N2** The SYSTEM entry of the DACL is not needed by anything in the design. Harmless.
- **N3** `FILE_CREATE_PIPE_INSTANCE` is in the user's grant; the one-instance limit and the broker holding the
  instance for its whole life are what stop a second server. Holds as long as nobody raises `nMaxInstances`.
- **N4** "Three refused clients end the broker" (pipe row of 2026-11-21) is not in `pipe.rs`; it is
  M3-BROKER-CORE's. Any same-user process can spend the three refusals: a denial of service inside the trust
  statement, accepted.
- **N5** Whether a local client can set the pid `GetNamedPipeClientProcessId` returns
  (`FSCTL_PIPE_SET_CLIENT_PROCESS`): from reading, npfs takes that control only from kernel mode (the SMB server),
  and `PIPE_REJECT_REMOTE_CLIENTS` closes the SMB loopback route. Not run. Worth one row in `m3-broker`. If it
  were possible the result is T14's accepted state (a same-user client is taken for the UI), not more.
- **N6** `act_service.rs:2952-2968`: the privileged owner write also reaches a key the SCM made below the
  restored service's key, not only "a key this undo created" as the rows and `reg_write.rs` say. It is still
  inside the tree the undo restores and the owner is the recorded one. Wording only.
- **N7** `secure.rs:541-551`: names that differ from the final path in non-ASCII case are refused. Safe side.
- **N8** A machine whose `ProfileList\ProgramData` is on another volume cannot start the broker
  (`store_integrity`). Matches the row's trigger.
- **N9** A user who creates `C:\ProgramData\Purge` before Purge is installed owns it; the broker then refuses to
  start until `install.ps1` replaces it. `install.ps1` must not adopt an existing directory.
- **N10** `check_deps` does not look for `#[path]` or `include!` that reach into another crate's `src`. An
  insider route, outside the brief (feature, dev-dependency).
- **N11** `Dispatcher::call` returns `serde_json::Value` (`table.rs:359-364`): result types are by convention.
  A typed `respond::<M>()` in M3-STDIO and M3-BROKER-CORE would make the fixtures binding.

## The attacks of the review point

| Attack | Result |
|---|---|
| Reach an Execute method over stdio | Not reachable. `route` looks the name up with `C::TRANSPORT` (`table.rs:289-296`), `lookup` needs the row served on the transport and in its mask (`:166-170`), `Transport::mask` is the only maker of a `SetMask` (`sets.rs:53-70`, `:95-100`; private field, private `of`, no `Default`, no `Deserialize`), `CallSet` is sealed (`table.rs:247-250`, `methods.rs:1366`) and `StdioCall` has no Execute or Propose variant (`methods.rs:1412-1422`); the `_` arm answers `-32601`. A request name sent as a notification is dropped (`table.rs:313`). Below that, a release engine does not link purge-exec (rules 4a, 4c). |
| A path or a document in a broker request | None. Every pipe params type is `deny_unknown_fields`, the two untagged enums have disjoint closed forms, ids are parsed (`u-`, `s-`, `p-`, `e-`, `c-` + 16 lower hex; `SessionId` re-derived from its own calendar time, `exec/session.rs:153-177`; `OpId` an integer). Duplicate members are refused by the derived structs, in the envelope and in params. Leftover: `ProgramId` is free text without a backslash (S5); candidate ids are not unique by construction (M2). |
| Start the broker from a user-writable place | Refused: `trusted_install_dir` step 5 on the directory and every ancestor, then the executable itself (`start.rs:226-231`). The check runs after the loader: M1. |
| Another volume | Refused: the volume GUID path read from the directory's own handle against that of `GetSystemWindowsDirectoryW` (`secure.rs:552-556`). A `subst` or mapped letter fails the final-path comparison first (`:541-551`); a volume mounted on a folder is a reparse point (`:527-535`). |
| Planted directories | `ProgramData` from `ProfileList` with only `%SystemDrive%`, `%SystemRoot%`, `%windir%` filled from the kernel's Windows directory; any other variable is an error. `PURGE_KB_DIR` is not read by the broker at all and by the engine only unelevated or in `rig-exec` (unknown elevation counts as elevated). Spellings refused before anything is opened: relative, UNC, `\\.\`, `\\?\GLOBALROOT`, `\\?\Volume{..}`, `.`/`..`, empty components, stream syntax, trailing dot or space, 8.3 names. |
| A second client, a fake pipe | First instance only, one instance, remote clients rejected, protected DACL (user, SYSTEM), medium label with no-write-up: a second server gets access denied or busy, a low-integrity or AppContainer process cannot open it, a client that is not the expected process fails `Peer::check` on pid, creation time, image, account or token. A squatter makes the broker exit (`NameTaken`). The fake-server side is the UI's check (not in this wave). |
| Keep the privilege on after its scope | Not found. `with_restore_privilege` (`privilege.rs:186-243`) changes nothing on the thread before `SetThreadToken`; every earlier `?` only closes token handles; the revert guard is declared after the copy, so it drops first, also on unwind; a failed revert aborts. The process token is opened with `TOKEN_DUPLICATE` only. In `reopen_and_set_owner` the backup-intent handle is made and closed inside the closure and one `NtSetSecurityObject(OWNER)` runs under it; a non-owner part is refused before anything is opened; the reopen is by empty name relative to the checked handle, so no name is resolved twice and the link check on `self` covers the same object. |
| Break check-deps with a feature or a dev-dependency | Not broken. A new engine feature that pulls purge-exec shows in "every feature but rig-exec"; a default feature shows in the release tree; a new binary package is covered by the dependents list, the `write` askers and its own release tree; an optional dependency of the broker is an implicit feature and fails "no feature"; `dep?/write` and renamed dependencies are handled; resolver 3 keeps dev-dependency features out of `-p` builds and the dev listings are checked anyway. Gaps found are outside that brief: S2, S3, S8, N10. |

## Writer choices

Accepted unless a row says otherwise.

| Package | Choice | Ruling |
|---|---|---|
| M3-S0 | temporary `TEMP_EXEC_DEPENDENTS` | Gone in M3-DEPS (`EXEC_DEPENDENTS`). Accept. |
| WIN-PIPE | 1 name of 32 hex digits; 2 SID form check before SDDL | Accept. |
| WIN-PIPE | 3 `FILE_GENERIC_READ\|WRITE`, one instance | Accept (N3). |
| WIN-PIPE | 4 medium label, no-write-up and no-read-up | Accept. |
| WIN-PIPE | 5 in the `read` feature; 6 `PipeError` | Accept. |
| WIN-PIPE | 7 64 KiB buffers, no read timeout, 30 s write | Accept for the served connection. **Reject "no read timeout" for the first read** (S1). |
| WIN-PIPE | 8 refused client: disconnect, wait on the same instance | Accept; the count of three is BROKER-CORE's (N4). |
| WIN-PIPE | 9 image check by exact path, not file identity | Accept, with S7 (the file's descriptor once at start). |
| WIN-PIPE | 10 client token equals the process's token; 11 refuse when impersonating; 12 abort on failed revert | Accept. |
| WIN-PIPE | 13 parent exit between bounded reads | Accept; not in `pipe.rs`, to be seen in BROKER-CORE. |
| WIN-PIPE | binding: read the first line, then `peer()` | **Amend** (S1): `peer()` first where the VM confirms it. |
| WIN-PRIV | 1 copied token and `SetThreadToken` | Accept. |
| WIN-PRIV | 2 two privileged uses in purge-win, the literal only in `restore_luid` | Accept; rule 4e matches the code. |
| WIN-PRIV | 3 owner only under the privilege; 5 `NtOpenKeyEx` by empty name | Accept. |
| WIN-PRIV | 4 note text unchanged | Accept. |
| WIN-PRIV | public `thread_impersonates`, `restore_privilege_enabled` in read builds | Accept: they read, and the rig needs them for T10. |
| RPC | 1 one engine code with `kind`; 2 parse errors keep reading, oversize closes; 3 envelope rules | Accept. |
| RPC | 4 table with `served`, `cancellable`, `consent`; 5 sealed call sets, private mask | Accept. |
| RPC | 6 only `$/cancel` from clients | Accept. |
| RPC | 7 broker ids 64 bits; `ExpiryId` | Accept: they name objects in broker memory, guessing one gives a same-user client nothing it cannot ask for. |
| RPC | 8 `CandidateRef` from the scan's id | **Reject as the selection key without a uniqueness rule** (M2). |
| RPC | 9 `MediumHello` on stdio | Accept. |
| RPC | 10 params forms; 11 results take unknown members; 12 output limit | Accept. |
| RPC | 13 invented result shapes; 14 fixture names | Accept; `Warning.code` free text is display only. |
| RPC | 15 single-threaded `serve`; cancel check is the server's | Accept as bindings. |
| RPC | 16 no MCP or CLI transport; 17 schemars, `raw_value` | Accept. |
| RPC | `ProgramId` free text, own inventory only | Accept with the bindings of S5. |
| HARDEN | 1 data root from `machine_program_data` | Accept; better than the design text. |
| HARDEN | 2 exit codes 20, 21, 22 | Accept. |
| HARDEN | 3 event source not registered | Accept. |
| HARDEN | 4 unelevated engine: same root, no volume rule | Accept. |
| HARDEN | 5 stricter install-dir rule and its order | Accept. |
| HARDEN | 6 load flag "needs an owner" | **Not done; M1.** `StorageRoots::installed()` env-dependent: accept while only the rig CLI calls it; the broker uses `StorageRoots::new` on the checked root. |
| HARDEN | 7 `PURGE_TEST_*` for elevated tests | Accept. |
| TASKDLG | `GetProcAddress` lookup; ids; Cancel default; primary once on the last page; gate; Approved rule | Accept. `run` requires the callback's click, the returned button, the returned and the tracked tick, and no close request (`taskdialog.rs:446-450`). |
| TASKDLG | "no timer" | **Amend** (S6): no timeout answer; a timer that arms the button is allowed. |

## DECISIONS rows pending M3-R1

| Row | Ruling |
|---|---|
| M3-WIN-TASKDLG (80128d9) | **Confirm**, with one amendment to add: "no timer" means no timeout answer; the primary button may be armed by a timer about one second after the page shows (S6). Still open as written: paging, gating and close-from-another-thread on a VM. |
| M3-WIN-PIPE (6101ecb) | **Amend** the binding: "M3-BROKER-CORE identifies the client with `peer()` before it reads anything; a client that cannot be identified before its first write (`ReadFirst`) is a refused client. If the VM shows an identification-level client cannot be identified before the first read, the first read has a 5 s timeout and a small line cap, and a timeout is a refused client. Nothing is answered before `Peer::check` passed." Items 1 to 13 confirmed. The row's trigger did not fire: no way found for a local client to set its pipe pid (N5, not run), to squat the name, or to get in from low integrity or an AppContainer. |
| M3-RPC (f4c15b9) | **Amend** item 7: "`CandidateRef` is the scan's candidate id. The broker refuses to serve a scan in which two candidates share an id, and a tick carried to a rescan applies only when the id's target is unchanged" (M2). Add to the binding: "a `ProgramId` from the wire is only compared with the broker's own inventory and fingerprint index, never made into a registry path or a file name; a hive other than `HKLM` or the checked account's is refused" (S5). The rest confirmed; the trigger did not fire: no hole in `route` or `lookup`. |
| M3-WIN-PRIV (d5d0002) | **Confirm.** The "never ran" clause is superseded by the elevated run recorded in `wave2-writers.md` (2026-11-21 20:06, 2/2 and 3/3, R8b M1 fixed on the VM); the row should say so. Wording (N6): the privileged owner write is on a key below the service key this undo restores, created by the undo or by the SCM during it. |
| M3-HARDEN (b15a2bd) | **Amend** item 6: "`/DEPENDENTLOADFLAG:0x800` is **not yet** in the broker's build.rs (review M3-R1 M1); until it is, the imports resolved before `main` are covered only by the directory check, and T6's planted-DLL row is expected to fail once the broker has an import that is not a KnownDLL." And the reason: "the install-dir rule closes the load-path cases for an installed broker; the load flag, when added, closes them for a copy". Add: "`SetDefaultDllDirectories` failing is a start failure" (S4). Items 1 to 5 and 7 confirmed; the trigger did not fire: no spelling found that the install-dir check accepts. |

Also touched by this review, not pending: the hardening row ("An elevated `purge-engine` follows the same rule")
should read "withholds trust from its directories by the same rule; it does not refuse to start" (S9). The rule 4e
row matches `check_deps.rs`; S2 and S3 are additions to it.

## Verified to hold

- stdio cannot carry Execute or Propose: mask, table, sealed call set and the dependency rules, four separate
  layers (attack table, row 1).
- Envelope: non-UTF-8, non-JSON, batch, unknown member, duplicate member, id that is not a `u64` (null, negative,
  fraction, string) each get the documented error and never run a method; `params: null` and absent read as `{}`;
  array params `-32602`; a `$/cancel` with an id is `-32601`.
- Framing: a line over the limit closes the transport without buffering more than the limit; a split line is
  joined; the writer never emits a raw newline inside a message and refuses a line over 16 MiB.
- Pipe: created first-instance-only with one instance, remote clients rejected, DACL injection impossible through
  the SID (form check before formatting); overlapped operations are cancelled and waited for before their buffers
  go out of scope; a write timeout is reported as unframed.
- Impersonation in `peer()`: refused when the thread already has a token; the guard reverts on every path and
  aborts when the revert fails; only `OpenThreadToken` (as self) runs while impersonating; the process handle is
  opened before any comparison and kept in the `Peer`.
- `Peer::check` order and content: pid (twice), creation time, exit, image (ordinal, case-insensitive, no
  normalisation), account, client token equal to the process's token.
- `with_restore_privilege`: no thread change before `SetThreadToken`; revert before close; revert on unwind;
  abort on failed revert; process token never opened for adjust; refused when not held (1314) or when the thread
  impersonates; `pub(crate)` and `write`-gated; two references, both in `CreatedKey`.
- `reopen_and_set_owner`: owner-only (`sd.info == OWNER_SECURITY_INFORMATION`), link check, same-object reopen,
  handle closed inside the scope; its one caller reaches it only when group and DACL already equal the recorded
  ones (`restore_key_security` returns a note in that case alone) and re-reads the descriptor afterwards.
- Start checks: order elevated, own directory, own file, data root, store; nothing is read after a failure
  (pinned by the fake-facts tests); no directory from the environment in the broker; the manifest is
  `asInvoker`, no `uiAccess`, comctl32 v6 from the side-by-side store, embedded (so `.local` redirection does not
  apply).
- `trusted_install_dir`: every component opened without following, any reparse tag refused, final path equal,
  volume identity from a handle, admin-only chain with the leaf mask on the directory itself.
- Engine: `PURGE_KB_DIR` only unelevated or `rig-exec`; `ProgramData` from the machine; caches and the shipped
  directory only on the rule's volume when elevated, and never created elsewhere.
- check-deps: rules 4a to 4d and 4f against the manifests as they are (`resolver = "3"`, purge-broker without
  features, `rig-exec = ["dep:purge-exec", "purge-exec/fault-inject"]`, `write` asked for by purge-exec and
  purge-broker only); a wrong root in any listing is a violation, a failed cargo call an error.
- TaskDialog: no hyperlinks, command links or radio buttons (flags are exactly cancellation and size-to-content);
  Cancel is the default and what Esc and the close box return; a gated primary cannot approve unticked; a close
  from another thread can never come out as Approved.

## Not verified

- Anything on a VM: T6 with a planted DLL, T7 through a real `runas`, the low-integrity and AppContainer opens,
  the pipe pid control (N5), identification before the first read (S1), comctl32 v6 under the System32-only
  search (S4).
- The UI side of the pipe (server pid check), M3-BROKER-CORE, M3-STDIO and M3-CONSENT, which do not exist yet;
  the bindings above are for them.

## Fixes

Status of every M and S finding in the `m3-r1-fixes` worktree (branch `m3-r1-fixes`, cut from `baseline`
5201102). Nothing committed. The five DECISIONS rows are now `confirmed M3-R1` or `amended M3-R1`.

| Finding | Status | What changed |
|---|---|---|
| M1 | **Fixed** | `bins/purge-broker/build.rs` emits `cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800` for MSVC targets. A build and `dumpbin /loadconfig` on `target\debug\purge-broker.exe` show `0800 Dependent Load Flag`. |
| M2 | **Fixed** | `purge_plan::decide::colliding_ids` finds ids that name more than one merge target (folded owner and canonical target); `merge` drops every candidate of such an id, so no plan or `ScanDoc` can carry one id on two targets, and `plan_in::check_structure` keeps its refusal as the backstop. `pipeline::scan` reports each dropped id as a warning. `purge-plan` test `merge_drops_every_candidate_of_a_colliding_id` forces two targets onto one id. `CandidateRef` still carries the stable hash for ticks across rescans; a collision is now refused, not resolved by guessing. |
| S1 | **Fixed in M3-BROKER-CORE** | `serve::accept` identifies the client (`Link::identify`, `PipeServer::peer`) before it reads a byte; a client that cannot be identified before its first write (`ReadFirst`) is a refused client, as is one that fails any check, and nothing is answered to it. `peer_before_any_read` showed on the dev host that an identification-level, static-tracking client is identified before its first write; `tests/pipe.rs` pins it (`an_identification_level_client_is_identified_before_it_writes_and_is_served`) and shows a `cmd.exe` client (dynamic tracking) refused as `Unidentified`. Still to confirm on the VM after a real elevation. After identification the first line has 30 s and 4096 bytes. |
| S2 | **Fixed** | `RtlAcquirePrivilege` and `RtlReleasePrivilege` are in `PRIVILEGE_APIS`, with a test that names them outside `privilege.rs`. |
| S3 | **Fixed** | The test-item filter splits `cfg(all(…))` only at nesting depth 0 (`all_names_test`), so `all(not(any(miri, test, doc)), feature = "write")` stays production code. Test `cfg_all_test_is_only_test_code_at_the_top_level`. |
| S4 | **Fixed** | `start::restrict_dll_search` returns a `StartFailure` (exit 21) and `main` reports it; a failed `SetDefaultDllDirectories` no longer leaves the default search order. `taskdialog` loads `comctl32` with `LoadLibraryExW(.., LOAD_LIBRARY_SEARCH_SYSTEM32)`. The System32-only load still happens to be confirmed with the manifest test on the VM. |
| S5 | **Fixed** | `ProgramId::build` refuses control characters (NUL included) in the key name and the SID; the `methods.rs` module text now says `ProgramId` is free text compared only with the broker's own inventory and fingerprint index, never used as a path or file name. The M3-RPC row carries the two bindings. |
| S6 | **Fixed** | The primary button is disabled on `TDN_CREATED` and `TDN_NAVIGATED` when its page holds it, and armed by the first `TDN_TIMER` past a one-second delay (`TDF_CALLBACK_TIMER`); a gated primary stays with the verification box. Doc, state and flag test updated. `comctl32` v6 behaviour on a VM is still the unverified part. |
| S7 | **Fixed in M3-BROKER-CORE** | `start::check_with` judges `<install dir>\Purge.exe` (`Started::client_image`, the `ExpectedPeer.image`) and every file directly in `<install dir>\kb\baselines` with the per-file admin-only check, and the `baselines` directory with the directory rule; a user-writable one is `install_untrusted` (21) before the store is located. Missing `Purge.exe` is the same refusal. The engine settings keep `check_shipped_dir`, so the pipeline judges each baseline file again at load. |
| S8 | **Deferred** | This needs a design decision on build provenance (a marker file from `xtask release` versus a build-id check) and an `install.ps1` change; it is a release-process gap with no standard-user path. |
| S9 | **Fixed** | The elevated-hardening row now says the engine withholds trust from its directories by the same rule; it does not refuse to start. |

N6 is folded into the M3-WIN-PRIV row; N5 stays a note for the broker package. M1 was verified by a build;
everything that needs a VM (S1, S4's comctl32 load, S6's dialog, S7's peer image) remains VM work.
