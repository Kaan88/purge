# M2 wave 1 review

Verdict: accept with required changes.

Reviewed: commits 00f3028..8a456ff on branch m2 (purge-guard `live.rs`, purge-win `fs_write.rs`, `secure.rs`, `reg_write.rs`, `sr.rs`, `rm.rs`, `appx_write.rs`, purge-model `exec/{op,journal,regbackup,session}.rs`). Reviewer: independent agent, 2026-11-15, Windows 11 build 26300, unelevated.

Findings: 1 blocking, 8 should fix, 8 minor. Findings that change a public API or an on-disk format are marked [API] or [FORMAT] and come first within each severity.

"Ran" means I ran it against a copy of commit 8a456ff in a temp directory (integration tests against the public API, unelevated). "Reasoned" means I read the code and did not run it.

## Blocking

### B1. `MoveHandle::rename_to` resolves the destination by path again, after the gate has checked it [API]

- Severity: blocking.
- Where: `crates/purge-win/src/fs_write.rs:334` (`rename_to`), with `crates/purge-guard/src/live.rs:1017-1051` (`DestinationFacts`, `check_destination_parent`) and `live.rs:1139` (`check_undo_path`).
- What is wrong: the gate judges the destination parent from facts "read from a handle on that directory". `rename_to` takes an absolute path and lets the kernel walk it again, so a reparse point planted in the parent after the check is followed. Nothing in either API ties the checked handle to the rename. `rename_into` (line 343) does tie them, but both are public and the by-path one is the shorter call. On undo the original parent is often a directory the user can write to, the file content came from the user, and the executor is elevated: that is a file plant into any directory the user names.
- Shown by (ran): open a handle on `userdir`, read final path and tag (plain). Rename `userdir` away and create a junction `userdir` to `protected`. `MoveHandle::open(quarantine\payload.dll).rename_to(userdir\payload.dll)` returns `Ok` and the file is in `protected`. The same sequence with `rename_into(&checked_handle, "payload.dll")` puts the file in the directory that was checked (now `userdir.old`) and nothing in `protected`.
- Smallest fix: take `rename_to` out of the public surface (keep it `#[cfg(test)]` or `pub(crate)`), so the only rename the executor can call is `rename_into` with the handle whose facts went to `check_quarantine_destination` or `check_undo_path`. State in the doc of `DestinationFacts` that the handle must be kept and passed to `rename_into`.

## Should fix

### S1. The key path the gate tells the executor to open runs through a real registry link for 32-bit `HKLM` classes [API]

- Severity: should fix.
- Where: `crates/purge-guard/src/live.rs:676-715` (`KeyProbe`, `key_probe`), `live.rs:720` (`check_ancestors`); the spelling comes from `crates/purge-model/src/target.rs:352` (`render`).
- What is wrong: for a key in the 32-bit view of `HKLM\SOFTWARE\Classes` the canonical key is (K32, `SOFTWARE\Classes\...`) and `KeyProbe.key_path` spells it `HKLM\SOFTWARE\WOW6432Node\Classes\...`, documented as "This is the key to open", with the ancestor `HKLM\SOFTWARE\WOW6432Node\Classes` in `KeyProbe.ancestors`. On Windows 11 that ancestor is a registry link to `\REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node`. An executor that follows the documented contract (probe each listed ancestor by itself) gets `RegLink` (`live.g11.ancestor-is-link`) for every 32-bit COM class, type library and interface key under `HKLM`, and `WKey::open` of `key_path` in the 64-bit view fails with `LINK_ON_PATH`. It fails closed, but it removes a large class of leftovers from what M2 can execute, and it invites a special case in the executor that skips an ancestor.
- Shown by (ran): `key_probe` of `HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{...}` lists the ancestor above; `WKey::open(Hklm, "SOFTWARE\WOW6432Node\Classes", K64).is_link()` is `true`; `WKey::open(Hklm, "SOFTWARE\WOW6432Node\Classes\CLSID", K64)` is error 1921; `check_key` with that one ancestor as `Link` refuses with `live.g11.ancestor-is-link`. The route that works is `WKey::open(Hklm, "SOFTWARE\Classes\CLSID", K32)` (the `CanonKey` view and path), where no component is a link. `SOFTWARE\WOW6432Node\...` with K32 is error 2. Under `HKU\<SID>_Classes\WOW6432Node` there is no link and both routes agree.
- Smallest fix: let `KeyProbe` carry, for the key and for every ancestor, the (root, view, path) triple to pass to `WKey::open` (path without `WOW6432Node`), keep the wire spelling only as the label that facts are matched by, and correct the doc of `key_path`. Add a test that runs `key_probe` and `WKey::open` together on a 32-bit `HKLM` class key (read only, runs unelevated).

### S2. `StoreScope` authorises whatever directory the caller writes into it [API]

- Severity: should fix.
- Where: `crates/purge-guard/src/live.rs:902-931` (`StoreScope`, public fields, `dir_of`), used by `check_store_item` (`live.rs:969`) and `check_quarantine_destination` (`live.rs:1074`).
- What is wrong: the own-store exemption is the only rule `check_store_item` applies before an expiry delete (no deny-list runs there), and the scope is two free-form strings with one floor: three path segments. It is not tied to Purge's roots or to a session id. The package spec asked for `quarantine_destination_ok(dest, purge roots, ...)`. A wrong scope turns the exemption into "delete anything below this directory".
- Shown by (ran): with `session_dir = C:\Windows\System32\config`, `check_store_item(Remove, C:\Windows\System32\config\SAM)` is `Ok`. With `session_dir = C:\ProgramData\Purge` (three segments), an item in another session's directory is `Ok`. With `session_dir = C:\ProgramData\Purge\sessions`, `sessions\index.json` is `Ok`. With `quarantine_dirs = [C:\Users\tester\Documents]`, `check_quarantine_destination` into `Documents\000001\App` is `Ok`.
- Smallest fix: make the fields private and build the scope with a constructor that takes the store roots and a `SessionId` and derives `<sessions root>\<id>` and `<quarantine root>\<id>`; require that the last segment of every directory is that session id. The test-support roots in temp directories still work with this.

### S3. The registry backup has no volatile flag, so a volatile tree cannot be restored [FORMAT]

- Severity: should fix.
- Where: `crates/purge-model/src/exec/regbackup.rs:258-276` (`KeyNode`).
- What is wrong: `WKey::flags` reports volatility and `WKey::create_subkey` takes `volatile` with the doc "the executor passes `false` except when a backup recorded a volatile key", but `purge.regbackup/1` has no field for it. A restore then creates every key non-volatile. Below a volatile parent that fails; below a persistent parent it turns a volatile key into a permanent one.
- Shown by (ran, under `HKCU\Software\PurgeReview-<random>`, removed afterwards): a non-volatile `create_subkey` below a volatile key fails with error 1021 (`ERROR_CHILD_MUST_BE_VOLATILE`); the volatile one succeeds.
- Smallest fix: add `volatile: bool` to `KeyNode` now, while no document has been written (with `#[serde(default)]` if old samples must keep reading).

### S4. The journal does not record the exemptions an item was removed under [FORMAT]

- Severity: should fix.
- Where: `crates/purge-model/src/exec/journal.rs:150-180` (`Validated`, `Intent`); needed by `crates/purge-guard/src/live.rs:1126` (`UndoPathCheck.exemptions`) and `live.rs:1191` (`check_undo_key`).
- What is wrong: undo must pass "the exemptions the item had when it was removed" to the gate. They are not in the journal, so undo has to derive them again from the scan sidecar with whatever derivation the engine has on the day of the undo (up to a year later). Without them, undo of an item that needed one is refused by the deny-list: an all-users Start Menu shortcut (`tier_a_start_menu_entry`), a `shell`/`shellex` skeleton key (`proven_owned_skeleton`), a `Session Manager\Environment` segment (`environment_segment_edit`).
- Shown by (reasoned): `check_undo_path` runs `deny.check` on the original path with `check.exemptions` (`live.rs:1152`); `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\App\App.lnk` is denied by the `ProgramData\Microsoft` rule unless `tier_a_start_menu_entry` is set.
- Smallest fix: add the four booleans to `Validated` (or `Intent`) as a small struct, written at validation.

### S5. A registered boot-time move leaves no record of the pair that was written [FORMAT]

- Severity: should fix.
- Where: `crates/purge-model/src/exec/op.rs:583` (`ItemOutcome::PendingReboot`), `journal.rs:197` (`Done`); `crates/purge-win/src/fs_write.rs:1010` (`strip_marker`, private), `fs_write.rs:1019` (`BootMove`).
- What is wrong: `BootMove.pair` is documented as "the pair exactly as it stands in the list ... this is what `remove_pending_pairs` needs", and `remove_pending_pairs` matches unit for unit. The journal has nowhere to keep it. After a crash, or at undo or reconcile, the executor has to rebuild the pair from the paths, and that misses the `*<digit>` spelling `move_delay_until_reboot` itself allows for; the helper that strips the marker is private.
- Shown by (reasoned): `remove_pairs_from_value` compares `src` and `dst` exactly (`fs_write.rs:791`); a pair stored as `*1\??\C:\x` does not equal `pending_pair(src, dst)`.
- Smallest fix: give `PendingReboot` (or `Done`) the stored `src` and `dst` strings and whether the registration was confirmed. If the format must not change, export a `matches_pending(&PendingPair, src, dst)` that applies `strip_marker`.

### S6. `Intent::is_consistent` accepts an inverse that addresses something else than its op

- Severity: should fix.
- Where: `crates/purge-model/src/exec/journal.rs:190` (`is_consistent`), `op.rs:511` (`Inverse::fits`).
- What is wrong: the documented reader check ("a reader refuses a journal with an intent that fails this") compares only the kinds. The inverse repeats the addressing fields of the op (`original_path`, `key`, `name`, `segment`), and undo acts on the inverse's copy. A record whose two halves disagree passes the check.
- Shown by (ran): an intent with `QuarantineMove{path: C:\Users\me\AppData\Local\App}` and `MoveBack{original_path: C:\Windows\System32\evil, quarantine_path: C:\Windows\System32\drivers\etc}` and `pre: Absent` has `is_consistent() == true`. So has `EditSegment` on `HKLM\SOFTWARE\A` value `Path` with `ReinsertSegment` on `HKLM\SOFTWARE\B` value `Other` and another segment.
- Smallest fix: in `is_consistent`, require `original_path == path` for `MoveBack`, `path` equal for `RecreateDir`, `key`/`name`/`segment` equal for `ReinsertSegment`, and that `pre` is the facts kind the op needs (`File` for path ops, `Key`/`Value` for registry ops). Extend `intent_lists_its_backups_and_checks_itself` (`journal.rs:661`) with the mismatching cases.

### S7. `create_file_secure` follows a dangling file symbolic link and creates its target

- Severity: should fix.
- Where: `crates/purge-win/src/fs_write.rs:643-667` (the `CreateFileW` call at 649-659).
- What is wrong: the doc says the call "fails with `AlreadyExists` if a file or a file link has that name; nothing existing is ever opened". `CREATE_NEW` without `FILE_FLAG_OPEN_REPARSE_POINT` follows a symbolic link whose target does not exist and creates the target, with the caller's descriptor, and returns it open for writing. The journal, backups and the index are created through this call.
- Shown by (ran): a symbolic link `journal.jsonl` to a missing `victim.txt`; `create_file_secure(journal.jsonl, sddl)` returns `Ok` and `victim.txt` exists. With `FILE_FLAG_OPEN_REPARSE_POINT` added, the same `CREATE_NEW` fails with error 80 (`ERROR_FILE_EXISTS`) and creates nothing. A dangling junction is refused today (`AccessDenied`), and `create_dir_secure` refuses dangling junctions and directory links (`AlreadyExists`).
- Smallest fix: pass `FILE_FLAG_OPEN_REPARSE_POINT` in `create_file_secure`. Add the dangling-link case to `secure_directory_and_file_creation` (`fs_write.rs:1482`), which only tests a junction with a live target.

### S8. A directory that is in use reports `AccessDenied`, which the error type documents as a rights problem [API]

- Severity: should fix.
- Where: `crates/purge-win/src/fs_write.rs:122-124` (doc of `FsError::AccessDenied`), `fs_write.rs:161-173` (`From<Win32Error>`).
- What is wrong: renaming a directory fails with error 5 while any handle is open on a file below it, whatever that handle shares. `FsError` maps 5 to `AccessDenied`, "the caller's token is not allowed to do this. Purge reports it and never raises its access". An executor that follows the type sends a locked install directory to `failed(AccessDenied)` and never to the retry and Restart Manager ladder of section 7.6, which is keyed on `SharingViolation`. The executor's own tree-walk handles have the same effect if one is still open.
- Shown by (ran): a directory with one file held open, once with read sharing only and once with read, write and delete sharing; `MoveHandle::open(dir).rename_to(...)` is `Err(AccessDenied)` both times. Opening the held file itself gives `SharingViolation`.
- Smallest fix: say so in the docs of `rename_into` and `FsError::AccessDenied`, and add a test. Better: on error 5 from a rename of a directory, return a distinct `FsError::InUseBelow` (or let the caller ask Restart Manager for the files below before it reports access denied).

## Minor

### M1. `BackupRef::is_session_relative` lets through names Win32 does not treat as plain files

- Where: `crates/purge-model/src/exec/op.rs:194`.
- What is wrong and shown by (ran): `reg\NUL`, `reg\CON.json`, `reg\a.`, `reg\a ` (trailing dot or space), `reg\...`, a name with a tab or NUL character, `reg\a*` and ` reg\x` are all accepted. Joined to the session directory and opened without the `\\?\` form, a trailing dot or space names another file and a device name may name a device.
- Smallest fix: per component refuse control characters, `< > " | ? *`, a trailing dot or space and DOS device names (the rules of `canon::check_segment`), or restrict backup paths to the two shapes the executor writes (`reg\<6 digits>.regbackup.json`, `def\<6 digits>.json`).

### M2. `RegTree::validate` leaves several things to "the reader"

- Where: `crates/purge-model/src/exec/regbackup.rs:315`.
- What is wrong and shown by (ran): a tree with `link: true` on keys, two siblings `Child` and `CHILD`, two values `v` and `V` in one key, a key name with a NUL, an empty SDDL and a root name with separators passes `validate()`. The doc of `KeyNode.link` says a reader refuses a tree with a link, but `validate` does not, and `has_link` is a separate call. `RegBackup.key` is free text and is not compared with the root name. The mandatory integrity label (SACL part) of a key is not captured, so a low-integrity key comes back at the default level.
- Smallest fix: refuse `link: true`, NUL in key names and duplicate sibling names in `validate`; add a `RegBackup::validate` that also checks `key` against the op's key at the call site.

### M3. The file wrappers accept stream syntax and names Win32 cannot address

- Where: `crates/purge-win/src/secure.rs:124` (`extended_units`), `crates/purge-win/src/fs_write.rs:343` (`rename_into`).
- What is wrong and shown by (ran): `MoveHandle::open("host.txt::$DATA").delete()` deletes the file and its final path reads `...\host.txt`; `open("dir::$INDEX_ALLOCATION").remove_dir_if_empty()` removes the directory; `open("host.txt:second").delete()` removes one stream. `rename_into` accepts the leaves `trail.`, `trail ` and `NUL` and creates those names. The gate refuses all of these on the lexical path (`canon.ads`, `canon.trailing-dot-or-space`, `canon.device-name`; ran), so this is a second line only.
- Smallest fix: refuse a `:` after the drive in `extended_units`, and a trailing dot or space in the `rename_into` leaf, unless a caller asks for them explicitly.

### M4. The exec documents accept unknown fields and out-of-range counters

- Where: `crates/purge-model/src/exec/*.rs` (no `deny_unknown_fields`); `op.rs:160` (`OpId`), `journal.rs:208` (`GroupEnd`).
- What is wrong and shown by (ran): `{"kind":"None","quarantine_path":"C:\\x","surprise":1}` reads as `Inverse::None`; a record line with an extra field reads; `OpId(0)` reads although ids count from 1; `GroupEnd{group: 0, ops: 9999}` reads. Duplicate fields, negative and fractional numbers, two records on one line and other schema ids are refused (ran).
- Smallest fix: decide it on purpose. Either `deny_unknown_fields` on the records undo acts on (`Intent`, `Inverse`, `ExecOp`, `RegBackup`), or a sentence in each module that additions need a new schema id. Check the counters where the journal is read.

### M5. Two facts the live gate takes on trust

- Where: `crates/purge-guard/src/live.rs:272` (`FileIdentity::is_valid`), `crates/purge-guard/src/canon.rs:139` (`GuardEnv::missing`).
- What is wrong and shown by (ran): an identity with volume serial 0 is valid. With `purge_dirs` empty, `check_path` on `C:\Program Files\Purge\purge-engine.exe` has no objection, because the install directory is protected only by the dynamic rule; `C:\ProgramData\Purge` and `X:\.purge-q` are refused by the built-in rules either way (ran).
- Smallest fix: treat serial 0 as unknown. Let the executor refuse to start with an empty `purge_dirs` (or add it to `missing()` for the execute-time list).

### M6. Delete-if-empty for keys has a window between the counts and the delete

- Where: `crates/purge-win/src/reg_write.rs:738` (`WKey::delete`).
- What is wrong (reasoned): `delete` refuses subkeys but removes a key with values. G13 is judged from counts the executor read earlier; a value written between that read and `NtDeleteKey` is deleted and is in no backup. The handle is the same, so the window is short, and the registry has no atomic form.
- Smallest fix: a `WKey::delete_if_empty` that reads `info()` and refuses `n_values > 0` immediately before `NtDeleteKey`, used for `DeleteKeyIfEmpty`.

### M7. Numbers above 2^53 are written as JSON numbers

- Where: `journal.rs:43` and `op.rs:429` (`volume_serial: u64`), every `FileTime`.
- What is wrong (ran for the Rust side): serde reads and writes them exactly, and a float spelling is refused. A reader that keeps JSON numbers as doubles (PowerShell, JavaScript) silently rounds a 64-bit NTFS serial and every FILETIME. The file id is already a hex string.
- Smallest fix: write `volume_serial` as a hex string like `file_id`, or note in the schema that readers need 64-bit integers.

### M8. Tests that cover one side only

- `crates/purge-win/src/reg_write.rs:1474` `views_are_separate_under_hklm_software` is ignored (needs admin), so no unelevated test opens an `HKLM` key in the 32-bit view. The read half runs unelevated and would have shown S1.
- `crates/purge-win/src/fs_write.rs:1482` `secure_directory_and_file_creation` plants only a junction with a live target (see S7).
- `crates/purge-win/src/fs_write.rs:1467` `sharing_violation_is_typed` covers a held file, not a directory with a held file below it (see S8).
- `crates/purge-guard/src/live/tests.rs:1668` and `:1898` test the store scope only with well-formed session directories (see S2).
- `crates/purge-model/src/exec/journal.rs:661` and `regbackup.rs:667` test shape only (see S6, M2).
- `check_protected_descendants` (`live.rs:865`) lets an unticked Likely or Weak item go with a ticked whole-tree parent, and `a_whole_tree_removal_does_not_take_a_protected_item_with_it` asserts that. It matches the decision of 2026-11-15 (only Blocked items protect), but the function cannot see the selection; worth a conscious yes from the coordinator (reasoned).

## Checked and found sound

- `live.rs` `check_path`: every fact is needed before `Ok`; unknown and contradictory facts refuse; the deny-list runs on the lexical and the final path; `\\?\` and `\??\` prefixes, forward slashes, case and a trailing separator are the same item; volume GUID, UNC, stream, dot-segment and trailing-dot final paths are refused; `%TOKEN%`, stream, dot and trailing-dot lexical paths are refused (ran 30 spellings). Hard refusals come before the soft one.
- `live.rs` `check_key`, `check_undo_key`, `check_ancestors`, `admin_only_ancestors`, `check_undo_path`, `check_quarantine_destination` (with a well-formed scope): read; no path to `Ok` with a missing fact found. `HKU\<SID>\Software\Classes` and `CurrentControlSet` canonicalise off their links, and those links are real on this host (ran).
- `reg_write.rs`: component-wise open with `REG_OPTION_OPEN_LINK`, link refusal before every mutation, `NtDeleteKey` on the inspected handle, create with disposition check. NT structure offsets (`KEY_VALUE_FULL_INFORMATION`, `KEY_VALUE_PARTIAL_INFORMATION`, `KEY_FLAGS_INFORMATION`), NTSTATUS handling (warnings are not success), buffer growth and bounds, handle ownership: no fault found. Link and volatile flags read correctly on live keys (ran).
- `fs_write.rs`: `FILE_RENAME_INFO` buffer size, alignment and termination; no replace flag in either class; disposition fallbacks; stream info parsing bounds; pending-rename parsing and byte-exact removal; SDDL descriptor lifetime; handle ownership: no fault found. A dangling junction and directory link are refused by both create calls (ran).
- `secure.rs`: descriptor read from the handle, `LocalFree` exactly once, SID length from the sub-authority count.
- `sr.rs`: vtable slot counts for `IWbemLocator`, `IWbemServices::ExecQuery` (slot 20), `IEnumWbemClassObject::Next`, `IWbemClassObject::Get`; `VARIANT` layout; release and `CoUninitialize` order; System32-only DLL load. `rm.rs`: `RmGetList` argument order and retry, session ended once. `appx_write.rs`: full-name validation before any call, no path from a failed or cancelled operation to `Removed`.
- `exec/*.rs`: hex and base64 readers accept one spelling only; schema ids are checked; `SessionId` refuses impossible dates, upper-case hex and anything that is not 33 characters; `resolve` refuses report-only and truth-only targets.
- The existing suites pass on this host in the copy: purge-guard `live` 44, purge-model `exec` 42, purge-win write modules 53 (7 ignored).

## Not checked

- `vm/` and rigtool (out of scope).
- Anything that needs elevation: `HKLM` writes, the real `PendingFileRenameOperations` write and `move_delay_until_reboot`, restore point creation and the throttle answer, `RmShutdown`, real AppX removal, `set_security` with a foreign owner.
- A second volume (`NotSameDevice`), ReFS, a case-sensitive directory, other Windows builds.
- `sr.rs`, `rm.rs` and `appx_write.rs` were read for FFI, layout and lifetimes only; their behaviour was not exercised beyond the existing unit tests.
- The test files were not read line by line: I read the test lists of all files and about a dozen tests in full.
- The M1a parts of purge-guard (`canon.rs`, `deny.rs`, `prefix.rs`, the rule tables) only as far as `live.rs` calls them.
- The generated JSON Schemas.
- Gate G7 depends on the process exposing cloud placeholders (`PHCM_EXPOSE_PLACEHOLDERS`, section 7.2). No code in the repository sets it yet; until the executor does, the placeholder facts fed to `check_path` can read as plain files.

## Clean-up

The probes ran in temp directories and under one key `HKCU\Software\PurgeReview-<random>`; both are removed. No file in the repository was changed except this report.
