# Pass eleven: independent review (2026-11-15) and what was done about it

Reviewer: a fresh agent on the strongest model, medium effort, read-only on the repository, with a scratch copy
for probes. It was given the change list of `engine-pass11-handoff.md` section 2 and the pass-ten review, not the
author's conclusions. Tree reviewed: the committed m1a.6 tree (`4f2f036d…`) plus the test-only fix of
`apppaths_key_of_a_file_that_outlived_the_uninstall_is_not_offered`.

**Verdict: accept with required changes** (findings 1 and 2 are small fixes; both reached Safe and ticked in a
probe run).

How it checked: read the current code of the named functions, copied `crates`, `bins`, `tools`, `kb` to a scratch
workspace and ran `cargo test -p purge-plan -p purge-scan` there (native Windows, msvc). Findings marked
"reproduced" come from probe tests appended to the scratch copies of `hostile.rs` and `assoc/main.rs`, run through
`ctx.run` and the policy like the table test. Not run by the reviewer: `purge-policy` goldens, `purge-engine`,
`xtask`, replay.

## Findings

Line numbers are those of the reviewed tree.

### 1. Danger (Safe, reproduced): a token anywhere in the value name exempts the data outside `Run`/`RunOnce`/`command`

- Where: `crates/purge-scan/src/framework.rs:797` (exemption), `:853-858` (`named_after_app`, id branch),
  `:1295-1303` (`is_command_place`).
- Input: no installer record and no snapshot entry; data
  `"C:\Users\tester\my tool.exe" --with "C:\Program Files\Mozilla Firefox\browser\x.exe"` in any of
  `HKLM\SOFTWARE\Other Vendor\Tool | my 308046B0AF4A39CB thing`,
  `HKLM\SOFTWARE\Other Vendor\Tool | C:\Users\tester\tools\308046B0AF4A39CB\notes.txt`,
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run | my 308046B0AF4A39CB thing`.
- What happens: REF-ANY `DeleteValue`, Safe, ticked, on `HarvestedToken:A/7 + PointsIntoInstallRoot:B/6 +
  DanglingRef:B/7`. `data_unproven` finds the data unproven, then drops the verdict because
  `named_after_app(name)` is true and `command` is false.
- Why it matters: this is review ten's item 5b, fixed only for the three key shapes `is_command_place` knew.
  `Policies\Explorer\Run` starts programs at logon and was not one of them. `RunOnceEx` values live in
  `RunOnceEx\<nnnn>` subkeys, so the `RunOnceEx` entry in the list never matched a real value.
- Asked for: required, treat every start place as a command place; recommended, let an id in the name exempt only
  when the name is the id itself or the id plus a known suffix.

### 2. Danger (Safe, reproduced): number types pass by type tag, whatever the data holds

- Where: `framework.rs:742-749`.
- Input: `HKLM\SOFTWARE\Other Vendor\Tool | firefox.exe`, type `REG_DWORD` (4), `REG_DWORD_BIG_ENDIAN` (5) or
  `REG_QWORD` (11), bytes the UTF-16 of the command line above, with an Inno `RegDeleteValue` record.
- What happens: Safe, ticked (`InstallerManifest:A/8`). The same bytes as `REG_BINARY` give Likely.

### 3. Danger (Safe, reproduced, narrow): binary text that is a path but not drive- or `\\`-shaped is not judged

- Where: `framework.rs:1307-1309` (`is_path_shaped`), used at `:753-757`.
- Input: same key, name and value record; `REG_BINARY` holding two NUL-separated runs: `%USERPROFILE%\my tool.exe`
  then `<app>\x.exe` (Safe, ticked); `\Users\tester\my tool.exe` then `<app>\x.exe` (Safe, ticked); the ANSI bytes
  of `C:\Users\tester\my tool.exe;<app>\x.exe` (Safe, ticked). Control with a drive path first: Likely.
- It needs the installer's record on that exact value, so reach is small.

### 4. Correctness (foreign item offered, Likely): `bare_name_leads_elsewhere` answers "not elsewhere" too early

- Where: `crates/purge-scan/src/reg_apppaths.rs:170-192`.
- 4a, reproduced: `HKLM\SOFTWARE\Classes\Applications\Code.exe\shell\open\command` leads into the removed install;
  the user hive's key of the same name is a portable copy's; `FileExts\.md\OpenWithList | a = Code.exe`. The entry
  and its `MRUList` letter are offered. The loop returned `false` at the first hive holding an own path, and HKLM
  comes first; the user's key is the one in effect.
- 4b, traced: `walk.complete` was never consulted there, so a portable copy's key that cannot be read in full
  yields no path and the entry is offered.

### 5. Correctness (`outlived`): gated on the whole verify-gone result, but its premise is only "the main exes are gone"

- Where: `reg_apppaths.rs:162-164`.
- Input: Post or External mode; the uninstaller removed the app's files but left its Uninstall key (or the MSI
  state is not "unknown"); the user's `rg.exe` is still in the root. `App Paths\rg.exe` is listed again (Tier B,
  Likely, never Safe).
- Related, low: the "every path outlived" test uses `all`; `any` would be the cautious reading.

### 6. Correctness (collapse): an unticked whole-tree parent is checked only against four blocker kinds

- Where: `crates/purge-plan/src/collapse.rs:137-147`.
- Input: a Likely or Weak `Quarantine`/`DeleteKey` parent above a descendant Blocked with `SharedRefcount`,
  `ExistedBeforeInstall`, `WindowsBaseline`, `MicrosoftSystemTarget`, `TrustedInstallerOwned`, `DenyListed` or
  `SharedIid`. The parent gains nothing and stays tickable; ticking it takes the kept item with it.
- Put as a decision: either the executor refuses a parent with a Blocked descendant, or these give the parent a
  blocker too.

### 7. Danger (low, predates this pass): `prefix::eq_ci` can call two different NTFS names equal

- Where: `crates/purge-guard/src/prefix.rs:36-49`. Rust lower-casing maps U+212A (Kelvin sign) to `k`, U+2126 to
  `ω`, U+212B to `å`; NTFS and the registry keep those names apart. A value naming `...\Programs\<U+212A>odi\x.exe`
  was accepted as inside the root `...\Programs\Kodi`.

### 8. Low

- `framework.rs:710`: when the value read fails, `named_after_app` exempts even in a command place.
- `reg_software.rs:1134-1157` (`names_a_path`): complete binary data over the scan limit yields no strings and so
  "names no path". Text after a `REG_SZ` NUL and relative or rooted commands are not seen either.

### Test gaps

Eight mutations applied together left the `purge-plan` and `purge-scan` suites passing: `!outlived` removed in
`bare_name_leads_elsewhere`; `!walk.complete` removed in `exe_key`; `!is_complete()` removed in `names_a_path`;
the vendor-word filter of `other_app_named`; `:/` and `\\` removed from `is_path_shaped`; a `ContainsOtherApp`
descendant no longer counting in `objection`; an `OwnedByInstalledMsi` descendant no longer counting; only Likely
parents in `is_offered_whole`. Missing from the table in `hostile.rs`: number-typed raw data, binary runs that are
not drive-shaped, id-bearing names outside `Run`.

### Review items 1 to 8 of review ten

Made in full: 1, 2, 4, 6, 7, 8. Item 3: made, except findings 2 and 3. Item 5: 5a made; 5b only for the three
command-key shapes (finding 1).

### Looked at, nothing found

- Collapse termination: guaranteed. Every demotion adds a blocker the parent does not carry; blockers are never
  removed by `redecide` or `guard_and_policy`; `revalidate` only removes `EmptyAfterPlan` and nothing adds it back.
- `is_one_path` and `ListEntry::read` against quoting, `;`, the new characters, control characters, stream colons,
  `..` and dot-blank segments, `/` separators, 8.3 names, trailing dots and blanks, UNC, `%VAR%` expansion: all err
  to "unproven".
- `has_text_after_nul`, `ScanCtx::run` and `seal`, `in_ref_snapshot`.
- The band floor in `band.rs`: cannot give Safe; hard blockers return first.
- Over-caution: nothing large. `other_app_named` blocks on token subsets (`Microsoft\Visual Studio` while VS Code
  is installed) and names the wrong app; `\\?\` paths are refused.

### Not covered by the reviewer

The 610 live-mode rows; `purge-exec` behaviour on a ticked parent; `matches_product_subfolder` looseness;
`RegValueChanged` targets; `cls_assoc/handler.rs`; `xtask/replay.rs`; the `WOW6432Node\Classes` alias spelling in
`nests_in`.

## What was done

| # | Done | Where | Pinned by |
|---|---|---|---|
| 1 | Start places are one function, `is_start_place`: `Run`, `RunOnce`, `RunServices`, `RunServicesOnce` under `CurrentVersion`, `Policies\Explorer\Run`, `CurrentVersion\RunOnceEx` and the keys below it. They are command places, and never the app's own place by an installer key record (the new test found that a logged whole-key delete of `Policies\Explorer\Run` still made it one). The id route of `named_after_app` needs an id-shaped name (`is_id_shaped`: no blank, separator, colon, variable, list, quote or redirection character) | `framework.rs` | `hostile::an_id_inside_a_name_does_not_excuse_the_data` |
| 2 | A number is `dword()` or `qword()`: exact length of its type | `framework.rs` `data_unproven` | `hostile::text_under_a_number_type_is_read_as_text` |
| 3 | `is_path_shaped` also takes `%\` and a leading `\`; `ansi_runs` reads text of one byte per character | `framework.rs` | `hostile::binary_text_that_is_a_path_of_any_shape_is_judged` |
| 4a | Every hive's key is asked; any that leads elsewhere answers "elsewhere" | `reg_apppaths.rs` `bare_name_leads_elsewhere` | `file_exts_entry_is_not_offered_when_either_hives_key_leads_elsewhere` |
| 4b | A key not read in full leads elsewhere | same | same test (a link below the user's key) |
| 5 | Gate: verify-gone passed, or the main exes gone with at least one main exe known. (Gating on `main_exes_gone` alone dropped `App Paths\rg.exe` from two live re-plans: with no main exe known it holds of nothing.) `all` kept: with `any`, an App Paths key whose `Path` value names the surviving root folder would be dropped | `reg_apppaths.rs` `outlived` | `apppaths_key_of_a_file_that_outlived_the_uninstall_is_not_offered` |
| 6 | No engine change. Recorded as a requirement on the M2 executor (`docs/DECISIONS.md`): a ticked parent with a Blocked descendant is refused or the descendant is spared | | |
| 7 | `fold_char`: a character whose lower-case form belongs to another letter is left as it is. Used by `prefix::fold`, `prefix::eq_ci` and the reference matcher's `fold`. Checked on this host: `Kodi` and `\u{212A}odi` are two folders on NTFS and two keys in a hive. The other direct `to_lowercase()` calls in the crates (about 150) are not changed | `purge-guard/src/prefix.rs`, `purge-index/src/matcher.rs` | `prefix::tests::letters_that_only_unicode_lower_casing_joins_stay_apart` |
| 8 | An unreadable value in a command place is not excused by its name; `names_a_path` counts over-limit binary data and text after a string's end. Relative commands (`ff\firefox.exe "%1"`) are still not seen as paths | `framework.rs`, `reg_software.rs` | `apppaths_bare_exe_name_is_not_ownership` (extended) |
| gaps | Tests added for the `objection` kinds and the offered bands; mutations for every fix and for the eight named gaps are in `pass11/mutwin.py` (V1 to V28, the last four for the follow-up's fixes). Not done: the vendor-word filter of `other_app_named` | `collapse.rs` | `every_other_owner_blocker_reaches_a_parent_in_any_offered_band`, `a_blocker_the_parent_carries_is_not_reported_again` |

Effect on real captures: none. All 74 older captures (post and live modes) and the 29 gate-campaign captures give
the same items, bands, evidence tiers and blockers before and after these fixes.

## Follow-up review of the fixes (same reviewer, same day)

**Verdict: accept.** Findings 1, 2, 4, 5 and 8 closed; none of the earlier probes reaches Safe. A value named
exactly by the app's ProgID with the installer's record on it is still Safe whatever it holds (the documented
exemption). The reviewer did not mutation-test the new tests.

| Point | What | Done |
|---|---|---|
| Residual of 3 (danger, low, reproduced) | With a value record, a `REG_BINARY` whose first run is `tools\my tool.exe`, `2\Users\tester\my tool.exe`, `/Users/tester/my tool.exe` or `%MYTOOL%`, followed by `<app>\x.exe`, was still Safe and ticked | `is_path_shaped`: any UTF-16 run holding `\` or `/`, or two `%`. Rows added to `hostile::binary_text_that_is_a_path_of_any_shape_is_judged` |
| Over-caution of the fix for 3 (reproduced) | `ansi_runs` took bytes of 0x80 and above as printable and any run starting with `\` as a path: the app's own `StartupApproved\Run` switch `03 00 00 00 5C 41 7B 9A 22 DC 31 00` became Likely, as did UTF-16 text with U+5C3A | 8-bit runs are 0x20 to 0x7E only and count only with a drive (`X:\`, `X:/`) or `\\` in them (`holds_drive_or_unc_path`). Pinned by `framework::tests::binary_runs_read_as_paths` |
| Residual of 7 (danger, very low, reproduced) | `\u{10400}pp` and `\u{10428}pp` compared equal; Georgian and Cherokee pairs too, not checked on a volume by the reviewer | Checked on this host for every pair below U+10000: 194 letters are kept apart by NTFS and by the registry alike. `fold_char` folds nothing above U+FFFF and none of `WINDOWS_KEEPS_APART`. Pinned by `prefix::tests::letters_windows_does_not_fold_stay_apart` |
| Low | `is_start_place` does not ask for `Microsoft\Windows` above `CurrentVersion`; `Winlogon`, `Active Setup`, `Image File Execution Options` are not start places | Left: caution only, and fixed value names are judged by the list rule. In `docs/DECISIONS.md` as known limits |
| Checked, right | The id-shaped name rule and the start-place rule withhold nothing real that was found; `fold_char` on multi-character mappings | |
