# Local baseline handoff (paused 2026-11-22, fourth pause: harness switch, Claude credits ran out)

Branch `baseline`, pushed to `origin/baseline` (8c7142f). Design `docs/BASELINE_LOCAL_DESIGN.{md,json}`; every
decision of this work is a row in `docs/DECISIONS.md` (Post-M1b). This file is kept current so the work can be
continued from any harness: read it, then `git log --oneline -15` and `git worktree list`.

## FP CHECKED 2026-11-22 (branch `r3-fp-checked`; Fable review APPROVE with low findings, all fixed; pushed, NOT merged: the coordinator merges).
- Third round (review follow-ups, DECISIONS row "fp checked, review follow-ups"; origin/baseline 1b4886c merged
  first): an old inherited-ACL `fp` is replaced and its admin-owned plain `fp-<sha256>.json` files are moved over by
  handle (no exit 22); the elevated live engine judges each cache file (`admin_only_file`) before reading it by
  path; docs say directories are opened by path + final-path bound, files handle-relative; `rename_aside` gives
  the rejected object its kind's descriptor; the broker prunes its directories' rejects after 30 days at start;
  tests for the caches' real names through `DocDir`, concurrent replaces, and an elevated-only owner test
  (`#[ignore]`). purge-exec gained dev-dependencies purge-index and purge-source (tests only).
- Why: the R3 Fable re-review's follow-up. The elevated broker wrote, renamed and swept fingerprint files in
  `<data root>\fp` by path (and its MSI table cache wrote `fp\msitables` by path); `fp` was admin-only only by
  the installer's descriptor, never checked at run time. A user-writable `fp` would let a junction to
  `\RPC Control` + object symlink turn the rename into an arbitrary overwrite and the sweep into an arbitrary
  delete.
- Second round (coordinator rulings): Q1 accepted (noted in the "fp checked" row); `<data root>\baseline` (local
  baseline cache) made checked the same way, DECISIONS row "baseline checked". purge-exec: `storage/fp.rs` is now
  `storage/doc_dir.rs`, `FpDir` is `DocDir` (+ `list`, `remove`), `StorageRoots::baseline_dir`. purge-index:
  `LocalCache` reaches files only through the new `CacheFiles` trait (`PathFiles` by path for the engine,
  `LocalCache::with_files` for the broker). Engine: `Settings::local_baseline_source` / `LocalCacheSource`.
  Broker: `msitables.rs` is now `store_caches.rs` (`StoreTableCaches`, `StoreLocalCaches`, `CheckedCacheFiles`);
  `Started::broker_settings` sets both sources. Merged origin/baseline (91a930c, the m3_stdio timing fix).
  Checks after the merge: fmt, clippy (workspace, rig, mcp), check-deps, no-new-walks, gen-dto --check,
  baseline-sites: ok; purge-exec lib 495 (8 ignored) + all integration; broker 228 + 10 + 1; index 170 + 12 + 42 +
  21; engine default lib 70, engine 40, exec_cli 4; rig lib 75, engine 43, exec_cli 14 (parallel, all pass);
  `bash truth/bl.sh --self-test` PASS (12 cases); `BL_RUNS=7zip bash truth/bl.sh replay` (runs from the main
  checkout, output in a scratch dir): exact, none, merged, local exit 0; exact plan sha256 54c52a64... = the L3 ref;
  merged and local L5 against none: 0 violations. (The replay injects its views, so it does not exercise the
  cache files; the cache is covered by the unit tests.)
- First round fix (purge-exec `storage/fp.rs`): `StorageRoots::fp_dir` / `msi_tables_dir` = checked `Store` directories
  (relative to the checked data root, created with `Store` when missing, failing ones renamed aside);
  `check()` covers `fp`; `install_relaxed` creates it. `DocDir::{read, replace, sweep}` act relative to the
  checked handle only (files are `StoreFile`s; temp leftovers checked then deleted by handle; sweep only old
  plain one-link files). `at::Facts` gained `last_write`. Broker: fingerprint read/write/sweep through `DocDir`
  (`uninstall.rs`), MSI table cache `store_caches::StoreTableCaches` via the new `Settings::msi_table_source`
  (`pipeline::table_cache` takes it before any path). purge-index: `encode_cache_file`/`decode_cache_file`/
  `temp_file_name` (same format, same names). Engine unchanged by path (justified in DECISIONS row "fp checked").
- Effect on installs: an old `fp\msitables` (made by path, inherited DACL) is renamed aside once to
  `msitables.rejected-<utc>`; the cache refills.
- Checks (unelevated, TEMP=C:\purge-build\tmp): fmt --check, clippy --workspace --all-targets -D warnings, rig
  clippy (rig-exec + test-support), purge-mcp clippy, check-deps, no-new-walks, gen-dto --check: ok. purge-exec
  (fault-inject + test-support) lib 491 (8 ignored) + every integration target; purge-broker 227 + 10 + 1;
  purge-index 169 + 12 + 42 + 21; purge-engine default lib 69, engine 40, exec_cli 4; rig lib 74, engine 43,
  exec_cli 14 (engine run with --test-threads=1: `m3_stdio::programs_list_sends_raw_rows_first_then_patches`
  asserts a 50 ms wall clock and failed twice under the parallel run's load on this laptop, passes alone and
  single-threaded; it reads no fp/msitables).
- Symlink case of the tests runs only where the account may create symbolic links (skipped otherwise).
- Open: none blocking. The engine (medium and elevated CLI) keeps `DiskTableCache` and `PathFiles` by path, behind
  the admin-only directory rule (reasons in the two DECISIONS rows).

## M3-R2 M2: APPROVED 2026-11-22 (branch `r2-m2-inline`, pushed; the coordinator merges it).
- Fifth Fable review of 518b48b: changes needed (M7); M6, L4, interpreters, PATH closed → M7 fixed in 6e0d958;
  sixth Fable review of 9126b48: approved; optional follow-ups (`:` split, 8.3 names) in 2eb3360 (no further
  review needed). `origin/baseline` merged into the branch first (fea1208).
- Follow-ups: an argument part after a non-drive `:` is judged as a program name too (`/RUN:powershell` →
  `Medium`); an 8.3 short file name (`~` + digit, `POWERS~1.EXE`) in the program or any argument part → `Medium`;
  trailing dots and spaces are trimmed from file names (`powershell.exe.`).
- M7: any argument token naming a host or interpreter (`conhost --headless powershell ...`, `rundll32
  shell32.dll,ShellExec_RunDLL powershell ...`) makes the command `Medium`, for every program; `powershell_ise`
  and `dotnet` added to `INTERPRETERS`.
- Earlier round (fourth Fable review of f9bc039: changes needed (M6, L4); M5 + PATH filter closed → M6, L4,
  interpreter hosts fixed in 5268a09):
- M6: `sid` refuses any path not on a local fixed drive (UNC incl. `\\?\UNC\` and `\\localhost\c$`, mapped,
  `subst`, removable) for both the run and the data rule (DECISIONS H3 row). L4: a leading `//` is UNC in the
  argument check. Interpreter hosts (`pipeline::INTERPRETERS`: python, node, java, wsl, wscript, mshta, ...) are
  always `Medium`, also under `cmd /c`; `cmd`, `rundll32`, `regsvr32`, `msiexec` keep their judged rules.
- Earlier round (third Fable review of 3a135ed: changes needed (M5); H3, M3, M4, L3 closed → fixed in d3178fd):
- M5: a fully qualified argument path that does not exist is judged by its nearest existing folder, which must be
  admin-only (`is_admin_only_writable`); any other error is `Medium`. Drive-relative or `//` parts keep the old
  rule; switches, `-key:value`, URLs and GUIDs are not judged.
- PATH: an elevated run's machine `PATH` keeps only admin-only directories, in order (DECISIONS B1+S4 row); the
  command text is unchanged (B1). Medium runs unchanged.
- Earlier round (Fable re-review of 113b721: changes needed (M3, M4, L3; H3 in sid.rs) → fixed in 5a902e3):
- M3: `cmd` reads the raw line; `/s`, quotes cmd could strip differently, or `&<>()@^|` in the program → `Medium`.
  M4: a `cmd` program without an extension → `Medium`. L3: `NAME=value` values and `;`-parts are judged.
- H3 (new DECISIONS row): `sid::is_admin_only_executable` = the old chain rule + the file's parent directory grants
  no non-admin add-file/add-subdirectory. Used by the route, `should_run_medium` and the broker's `trusted_file`;
  the data rule `is_admin_only_writable` is unchanged for every other caller (`C:\ProgramData\Purge` would fail the
  run rule). Cost: vendor uninstallers in ProgramData folders that inherit the Users add right run at `Medium`.

## BL-FIX-UFH (branch `bl-fix-ufh` off `baseline` 9f40cca, 2026-11-22; pushed, NOT merged, Fable review next)
- Finding: the BL-GATE smoke (`truth/bl.sh replay`, frozen `7zip`, four views) had one S1 flip in the local view:
  `UFH\SHC` slot `0` (REF-ANY record, Likely, unticked), withheld by exact because the truth baseline holds it.
  Not inferred absence: the no-baseline path, which the local view cannot correct because the local baseline has
  no per-user state of a logged-on profile (S2 template, S3 `.DEFAULT`). Class over 10 local replays: 5 flips, all
  `UFH\SHC` slots. DECISIONS row 2026-11-22 "BL-GATE smoke finding".
- Fix (purge-scan only): `ScanCtx::in_baseline` takes a slot of a user's numbered-slot store
  (`framework::USER_SLOT_STORES`) as Windows' own without an exact baseline of this Windows, at every view below
  Exact and with none. Tests: `framework::a_user_slot_is_windows_own_below_exact`,
  `ref_any::record::a_slot_record_is_not_offered_without_a_matching_baseline` (the old below-Exact record test now
  uses a vendor key), `tests/privacy/ufh.rs::ufh_shc_below_exact_is_windows_own`,
  `reg_privacy::the_slot_store_is_a_framework_slot_store`; `baseline-sites` row updated.
- Re-check after merge: the full R3 replay (`bash truth/bl.sh replay`, 2.5-3 h) and `evaluate` with R4.

## R3 SINGLE WRITER + UI FOLLOW-UPS 2026-11-22 (branch `r3-single-writer`; Fable re-review APPROVED, merged into baseline).
- Verdict: two brokers (Leftovers' and History's/Vault's) could write one store at once with no guard. The index's
  read-modify-write lost entries and failed its read-back (measured: 6 unlocked writers x 4 updates, 18 sharing
  violations on `index.json.tmp`, 3 of 6 sessions gone from the index), so a finished cleanup could vanish from
  History or read as `Unindexed` and block every execute; one broker's recovery could `remove_unstarted` another's
  just-created session or write its report/index entry concurrently; two cap checks could both pass. A session's
  journal was already single-writer (append handle shares read only): no interleaved journal, no double restore.
- Fix (purge-exec, 3f9252d): `StorageRoots::lock_writer` = `sessions\writer.lock`, share mode 0, admin-only store
  file, OS-released on process death; taken by execute, undo, recovery, retry_held and purge for their whole run;
  2 s wait, then `StorageError::WriterBusy`. Broker (9468b56): `busy` for it, `writer_busy` probe before the execute,
  undo and recovery dialogs; fingerprint temp names per process. DECISIONS: two "(coordinator)" rows (R3).
- UI (eeb6806): models stay on the UI thread; Quarantine vault on `history.index` + `undo.run` +
  `quarantine.expiring/purge` (no sample data, no Empty quarantine); History "Check for interrupted cleanups"
  (`journal.pending` on the click, or after a `needs_recovery` refusal). Notes: `m3-notes/ui-history.md` (R3
  section), `broker-core.md` point 5, M3_DESIGN 3.6, install/README layout.
- Checks (unelevated, TEMP=C:\purge-build\tmp): fmt --check, clippy --workspace --all-targets -D warnings, rig clippy (rig-exec + test-support), check-deps, gen-dto --check (no RPC change), no-new-walks: ok. purge-exec (fault-inject + test-support) lib 481 (8 ignored) + every integration target incl. crash 16 and single_writer 2; purge-broker 223 + 10 + 1; purge-engine rig lib 73, exec_cli 43, engine 14. `dotnet build ui\Purge.App -c Release` 0 warnings; Purge.Client.Tests 130/130 (History 17, Vault 10, UiThread 3).
- Fable review (lock sound; advisory layer) fixed: pending read with the lock held (`pending_at_rest`, `busy` for
  `journal.pending` and the pre-execute check; UI lists nothing and drops stale marks on the next refresh); purge
  probes before its first dialog; execute re-checks interrupted sessions under the lock (`ExecError::NeedsRecovery`/
  `Damaged`); the probe retries 250 ms; stale fingerprint temporaries swept; two-process serialisation test, races of
  resume vs rollback, pending at rest. CLI verified: it writes only through the locked entry points. Checks: fmt,
  clippy (workspace, rig, mcp), check-deps, gen-dto ok; exec lib 484 + integration (single_writer 5); broker 227 +
  10 + 1; engine rig 73/43/14; App Release 0 warnings; UI tests 133/133.
- Open: one broker per app (ui-history.md); a fair queue instead of `busy` if users hit it; the VM rows in
  ui-history.md. Fable re-review: approve; follow-up: make `fp` a checked Store directory with handle-relative ops (defence in depth).

## BL-GATE runbook (rig tooling on branch `bl-gate-rig`, 2026-11-22; not run on a VM yet)
Rig rules apply (one VM at a time, VMPWFILE from the environment, never the clone/UT or DietPi). From the repo root,
with `target\release\purge-engine.exe` and `vm\rigtool\target\release\rigtool.exe` built from this tree and the tree
committed (m1b.sh BIND needs clean sources and rig inputs). Details: `vm\RIG.md` §8a (FirstRead) and §12.9 (R4).
```
$env:VMPWFILE = '<pw file>'
# A0  W4 settled first read (BL-RM S7; budget 60 s on the rig VM) -> vm\truth\baseline-local\bl-r?-*-firstread.json
.\vm\rig-baseline-local.ps1 -Mode R1 -FirstRead
.\vm\rig-baseline-local.ps1 -Mode R2 -FirstRead
# A3  exact smoke: first rig run with the BL-R1 M1 tree; run.json engine.hello must say asked/expected exact, ok true
.\vm\rig.ps1 -Mode m1b-app -App 7zip -RunPrefix blx-
# R4  Inbound (default VM): merged (exact hidden) and local (no shipped baseline), apps then traps
.\vm\rig.ps1 -Mode m1b-apps  -Base rig-base -RunPrefix blm- -HideExact -ExpectTrust merged
.\vm\rig.ps1 -Mode m1b-traps -Base rig-base -RunPrefix blm- -HideExact -ExpectTrust merged
.\vm\rig.ps1 -Mode m1b-apps  -Base rig-base -RunPrefix bll- -NoBaselines -ExpectTrust local
.\vm\rig.ps1 -Mode m1b-traps -Base rig-base -RunPrefix bll- -NoBaselines -ExpectTrust local
# R4  Clean-Pro: the same four with -VmName Purge-CleanPro (runs blm-m1bcp-*, bll-m1bcp-*)
```
Then score with `vm/truth/m1b.sh` (prefixes via `M1B_CLEAN=blm-m1b M1B_CP=blm-m1bcp`, then `bll-...`; S1: `danger_listed = 0`, every trap expectation met, merged and local, both VMs),
R3 replay (`--baseline-view` + `--l5-against`), W2/W3 from the plans; write `docs/BASELINE_LOCAL_GATE.md`.
Open risks (RIG.md §12.9): MSI table cache files under `%ProgramData%\Purge` land in the app truths (recall only);
an inbox Store update between warm-up and hello makes trust None (the run then fails its hello check).

## M3-R2 CLEANUP DONE 2026-11-22 (40e82ba code, 1f969c4 docs; pushed).
- `docs/reviews/m3/r2-review.md` has its "Fixes" section: every B/M/S finding, flagged point and note mapped to its
  fix commit and tests (test names checked against the tree).
- DECISIONS: nine "(coordinator)" rows dated 2026-11-22 (M1, B1+S4, M2, M3+point 7, S2+point 6, S5+point 1,
  S7+point 4, point 3+S3, point 2). The `plan_refused`-not-`gone` choice for a vanished session is argued there.
- Point 2: B4 in `M3_DESIGN.json`, T2 in `M3_DESIGN.md` and `m3-notes/undo.md` say "outside Purge's store"; new
  purge-exec test `an_unindexed_recovery_whose_journal_changed_after_the_preview_is_not_as_shown`.
- Nits fixed: N1 (no remove before the fingerprint rename), N2 and N8 (comments), N4 (threat row T17), N9 (exec.md,
  broker-flow.md). Deferred with reasons in the Fixes table: N3 (needs a purge-exec bind API change), N5 (measure
  the real dialog on the VM first), N6 (needs a fingerprint retention rule), N7 (changes the scan-claim rules).
- Checks: fmt, clippy -D warnings, check-deps, gen-dto --check ok; broker 218 + 10 + 1, exec lib 464 (8 ignored);
  `dotnet build ui\Purge.App -c Release` 0 warnings; UI tests 100/100. All unelevated.
- M2 residual: REWORKED PER FABLE, PENDING RE-REVIEW on branch `r2-m2-inline` (pushed, not merged). Fable's review
  of 6167e25 asked for changes (H1, H2, M1, M2, L1); the rework makes every `powershell`/`pwsh` line `Medium`
  (profile and HKCU module paths load even with `-File`/`-NoProfile`), `cmd` `Medium` without `/d` before `/c` or
  when it runs another host or a second program, and makes the comma handling quote-aware (DECISIONS M2 row).
  Cost: PowerShell and `cmd`-without-`/d` uninstallers that need admin run at medium and may fail visibly. Still
  untested on its own: the S2 vanished-session refusal of `plan.create`; the History page still shows sample data
  (S5 alerts only on the Leftovers result). The section "Still open from M3-R2" below is superseded by this one.
- Next: Fable re-review of `r2-m2-inline`, merge, then M3 per the design (warm/first-launch bench rows, VM backlog).
- **Still open from R2:** M2 residual: `route` accepts `powershell`/`pwsh` without `-File` (inline `-Command` or
  `-EncodedCommand`) as loading no file, so it can be broker-route. The DECISIONS M2 row rules it `Medium` (safe
  direction); change `command_loads_admin_only` in `bins/purge-engine/src/pipeline.rs` and get a Fable review
  (route rule = critical). The S2 vanished-session test is merged (bc0d558); the History page is on real data
  (merged from `r3-history`, `docs/m3-notes/ui-history.md`). The section "Still open from M3-R2" below is
  superseded by this one.
- Next: the M2 residual above, then M3 per the design (warm/first-launch bench rows, VM backlog below).

## COLD BENCH DONE 2026-11-22 04:00: PASS, p50 559.7 ms (limit 1000), 5 runs 544-584 ms, CPU 96-98 % idle.
Committed `bench/launch/cold-DESKTOP-K1F333G.json`, row filled in docs/M3_BENCH.md. Attempt 1 measured nothing
(script splat bug, `@args`; log kept as `C:\purge-build\cold\cold-attempt1-failed.log`); attempt 2 is the series.
Next: the M3-R2 cleanup ("Still open from M3-R2" below). Warm and first-launch rows of M3_BENCH are still TBD.

## (older) COLD BENCH SERIES RUNNING (started 2026-11-22 ~03:40, unattended; user asleep).
- The user's desktop-PC trial PASSED: the fe444fd installer installs, finds leftovers and deletes them.
- The user said "push as you go" (pushing no longer needs asking).
- Cold-after-reboot bench (M3_BENCH 9.2(e)) runs by itself: Startup-folder entry `purge-cold-bench.cmd` runs
  `C:\purge-build\cold\cold-step.ps1` at each auto-logon: one `bench-launch --cold` (run 1 with `--reset`) with the
  frozen `C:\purge-build\cold\purge` (= fe444fd ui-publish) and `xtask.exe`, then a reboot, 5 runs in all.
  Log `C:\purge-build\cold\cold.log`, count `count.txt`, `DONE` when finished (the Startup entry deletes itself).
  Stop it: create `C:\purge-build\cold\STOP`. Results: `bench/launch/cold-DESKTOP-K1F333G.json` (uncommitted).
- On resume: check `DONE` + `cold.log` (5 runs, exit codes, CPU-idle warnings), read the gate in the json, fill
  the cold row of docs/M3_BENCH.md, commit + push. Then the M3-R2 cleanup ("Still open from M3-R2" below).

## PAUSED 2026-11-22 02:45 (fifth pause: restarting Claude Code UNELEVATED).

Done this session (Claude Code, Opus 5.5, elevated): the "Recommended first move" of the section below.
- Dirty M1-writer files **stashed** (not dropped): `git stash list` -> "dirty M1-writer leftovers (unwanted, per
  handoff)". Drop it once nobody wants to inspect them.
- Installer copied out: `C:\purge-build\installer\Purge-Setup-0.1.0.exe` (SHA-256 matches the one below). The
  `inno-installer` worktree's `target/` may now be deleted.
- Merged into `baseline` (local, **NOT pushed**): `r2-s` (ea743b7), `r2-m1` (a7813b4, **no conflicts**),
  `inno-installer` (d4ee4c3, brings `r2-s7`). Then 3b9c9f6: purge-policy fix below.
- Checks on the merged tree: fmt, clippy -D warnings, check-deps, gen-dto --check, `dotnet build ui\Purge.App -c
  Release` (0 warnings), 100/100 UI tests: all green. Rust tests (elevated, from PowerShell): broker 218 + pipe 10
  + start, engine 68 + 40 + exec_cli + planted_env, rpc 31, exec integration tests all ok; exec lib 461 ok,
  2 fail **only because elevated** (owner = Administrators S-1-5-32-544, tests expect the user):
  `gate::tests::key_actions_and_emptiness`, `storage::tests::strict_policy_refuses_and_renames_aside_a_tree_owned_by_a_user`.
- Unelevated `xtask ci` (`PurgeCiUnelev`, 02:25) EXIT 1 on `purge-policy` `m1a_band_table_unchanged`: the
  golden.rs fingerprint was stale since M3-ENGINE-OUT 1f680df (two `None` fields added to the `cand` helper, no
  band row; proven by restoring golden.rs at 1f680df^, which passes on the old value). Fixed in 3b9c9f6 by
  re-keying `M1A_GOLDEN_FINGERPRINT`. The ci stopped at `cargo test --workspace`, so later ci steps did not run.

Next, in order:
1. Re-run the unelevated ci (`schtasks /run /tn PurgeCiUnelev`, log `C:\purge-build\ci-unelev-laptop.log`, ends
   with an `EXIT n` line); once unelevated, plain `cargo xtask ci` in the session works too. Expect all green.
2. Fable-medium review of 3b9c9f6 (M1a band guard = critical; fable-review-rule). Small: one constant + comment.
3. Ask the user, then push `baseline`. Then hand over the installer (desktop-PC trial, conditions below).
4. Remaining M3-R2 items ("Still open from M3-R2" below).

Resumed unelevated 2026-11-22: unelevated `xtask ci` ALL PASS on fe444fd; Fable approved 3b9c9f6; `baseline`
pushed (fe444fd). Installer rebuilt from fe444fd: `Purge-Setup-0.1.0.exe` 41.0 MB, SHA-256
`89767b0e537346cbb62bf219fd2595a4594d81a52bafd20ea3202064d0d83391`, kept as
`C:\purge-build\installer\Purge-Setup-0.1.0-fe444fd.exe` and copied over SSH to the desktop PC (192.168.1.115,
DESKTOP-9SOIUCB) as `Desktop\Purge-Setup-0.1.0-fe444fd.exe`, hash verified there. The older
`Desktop\Purge-Setup-0.1.0.exe` on that PC is the pre-merge b5b9fa4 build (b49ff9...): no M1 broker dialog, do not use.
Next: the user's desktop-PC trial (conditions below), then "Still open from M3-R2".

### Harness notes (this session)
- `build-installer.ps1`: run it as its own `powershell.exe -File` process (inside a PS 5.1 session, `*>` turns
  cargo's stderr into a terminating error under its `ErrorActionPreference=Stop`), and put
  `C:\Program Files (x86)\Microsoft Visual Studio\Installer` on PATH (the AOT link step calls `vswhere.exe`).
- Git Bash (MSYS) enables SeBackup/SeRestore in its own token when elevated; `cargo test` started from it fails
  `undo_tests::no_privilege_or_impersonation_outlives_a_request`. Run Rust tests from PowerShell (or unelevated).
- The suite assumes an UNELEVATED runner (owner checks). Elevated sessions give false failures.

## PAUSED 2026-11-22 (harness switch). Everything below is older history.

State: **M3 waves 1-5 are merged into `baseline` 8c7142f (pushed)**, plus M3-R2 fix round 1. The app can do a full
uninstall end to end in code. Four branches are FINISHED but **NOT MERGED** (see below). No build/runtime was left
running; no VM was started this session.

### Not merged, in merge order
1. `r2-s` 5b0b22a (parent 8c7142f) - M3-R2 S1 + S2 + S5, by Flash, all checks reported green
   (broker 204, exec 463/8 ignored, rpc 31, 98 UI tests; gen-dto ok; build 0 warnings).
   - S1: `serve.rs` `mark_broken` uses `try_send` + a `broken` AtomicBool, so a full 256-slot event channel can no
     longer stall the supervisor. Test: `a_full_event_channel_does_not_block_the_pipe_broken_signal`.
     Not reproduced end to end over a real pipe (only the flag path).
   - S2: a successful run spends **every scan of the program** (`Scan.program` + `spent`); `plan.create` refuses a
     spent scan or a vanished session; `plan.execute` also refuses a plan pre-created from a sibling scan.
     Tests: `a_run_spends_every_scan_of_the_program`,
     `a_scan_whose_session_vanished_cannot_be_planned_until_scanned_again`. Refusal kind for a vanished session is `plan_refused`
     ("scan again"), not `gone` - a judgement call.
   - S5: reconcile alerts reach the client - `UndoResult.alerts[]` / `OutcomeResult.alerts[]`
     (`Alert { op, original_path, moved_back }`), `HistoryItem.alert` mark, shown on the Leftovers "Put back"
     result panel; the live History page renders it too since `r3-history` (`docs/m3-notes/ui-history.md`).
     RPC + fixtures + schemas + `RpcModels.cs` changed.
2. `r2-m1` 743ca9a (parent 8c7142f) - M3-R2 M1 (broker consent dialog before `uninstall.run`), by Sonnet 5.5.
   Checks reported green (215 broker, 100 UI, gen-dto, 0 warnings). RPC: `RunParams.restore_point` (optional,
   display only), `uninstall.run` marked `consent: true` in `table.rs`, fixture + `RunParams.json` + `RpcModels.cs`
   hand-edited. Adds `text::shown_line` / `quote_line`. UI: waiting state + Retry bar in `UninstallPipeline.cs`.
   **Expect merge conflicts with `r2-s`** in `crates/purge-rpc/src/methods.rs`, `lib.rs`, fixtures/schemas and
   `ui/Purge.Client/Rpc/RpcModels.cs`. Merge `r2-s` first, then `r2-m1`; re-run `cargo xtask gen-dto` and
   `gen-dto --check` after resolving.
3. `r2-s7` 641dcf7 (parent 8c7142f) - M3-R2 S7: broker built for the Windows subsystem
   (`#![windows_subsystem = "windows"]` in `bins/purge-broker/src/main.rs`) and `BrokerLauncher.cs` uses
   `SW_SHOWNORMAL` instead of `SW_HIDE`; notes updated. dumpbin: "2 subsystem (Windows GUI)", load config still
   `0800 Dependent Load Flag`. Broker 201 + 10 + start test, 98 UI tests.
   **Already contained in `inno-installer`** (that worktree merged r2-s7), so merging the installer brings it.
4. `inno-installer` b5b9fa4 - Inno Setup installer (user asked for one; see below). Contains `r2-s7`.

### DIRTY main checkout - clear it before merging
The M1 writer left three partially-edited files **in the main checkout** (not the worktree), from running commands
with relative paths. They are not the committed `r2-m1` content and are NOT wanted:
```
bins/purge-broker/src/consent/view.rs
bins/purge-broker/src/flow_tests.rs
crates/purge-rpc/fixtures/pipe.uninstall.run.params.json
```
Do `git checkout -- bins/purge-broker/src/consent/view.rs bins/purge-broker/src/flow_tests.rs crates/purge-rpc/fixtures/pipe.uninstall.run.params.json`
before merging (or `git stash` if you want to inspect them). Untracked and harmless: `.claude/`, `EngineLink.cs`,
`vm/truth/m1b-evidence/budgets/`.

### Inno Setup installer (for the desktop PC)
- Script `install/inno/purge.iss`, builder `install/inno/build-installer.ps1` (builds engine + broker + AOT
  publish, runs ISCC), docs in `install/README.md` ("Inno installer" section).
- Built artifact (in the worktree, NOT tracked by git):
  `.claude/worktrees/inno-installer/target/installer/Purge-Setup-0.1.0.exe`
  42,953,088 bytes, SHA-256 `B49FF9107E82D0B0D910533F7D5C3A69FAD3469F83CF14C94766DA101FC61CB8`.
  **The user has not been told to install it yet and it has never been run** (needs elevation). It will be
  overwritten/regenerated by `build-installer.ps1`, so tell the user how to copy it to the desktop PC.
  **COPY THIS FILE OUT BEFORE DELETING `.claude/worktrees/inno-installer/target/`** (the disk-hygiene rule below
  would otherwise destroy the only built setup; it is git-ignored and takes minutes to rebuild).
- Layout: `%ProgramFiles%\Purge` (dir page disabled - the broker only trusts a protected Program Files path), the
  engine, the broker, the whole self-contained AOT publish tree (`SelfContained=true`,
  `WindowsAppSDKSelfContained=true`, `PublishAot=true` in the csproj - no .NET or Windows App Runtime needed on
  the target), `kb\`, and `setup\install.ps1`. Post-install runs `install.ps1 -ProtectOnly -DataRootOnly
  -SkipBuild` (creates `%ProgramData%\Purge` with protected descriptors + the "Purge" event-log source) then
  `install.ps1 -Check`; failure rolls the install back. Uninstall kills the three processes, removes the event
  source, files and shortcuts, and asks (default **No**) whether to delete `%ProgramData%\Purge` (quarantine +
  history).
- New `install.ps1` switches: `-DataRootOnly`, `-ProtectOnly`; protection pass extracted to `Protect-Tree`, which
  now also sets the tree root to the exact `ProgramFiles` constant. Self-test 120/0.
- Untested (target PC only): real elevation and resulting file owners passing `start.rs`, `-Check` returning 0,
  real broker start from the installed layout, `Purge.exe` running with no runtimes installed, uninstall +
  rollback, SmartScreen for an unsigned setup.

### What the user was told, and where the trial stands
- The user wants to see a UI that deletes things; they will install on a **desktop PC**, remove it easily, and
  will not risk important software. Trial conditions (from r2-review.md, last section): install with
  `install.ps1`/the Inno setup, restore point = always, a test app with a plain `.exe` uninstaller (7-Zip,
  Notepad++), keep the default ticks, no user-data item, no expired-quarantine purge, compare the dialog code
  with the UI's, close the UI if no dialog appears in ~10 s, keep a `rig-exec` engine build as the undo fallback.
- The user was told M1 was still open at trial time (broker had no dialog of its own); it is fixed in `r2-m1`.
  It is also now **essential** to merge `r2-s7` (console flash / window show state) for a clean first impression.
- Before the trial: check `HKCU\Environment` for values named like system variables (`ProgramData`,
  `ProgramFiles`, `SystemRoot`, ...). B1 is fixed, but a machine-scope route still depends on that hygiene.
- Recommended first move on the new harness: discard the dirty files, merge `r2-s` -> `r2-m1` -> `r2-s7`
  (or let the installer merge carry s7), run on the merged tree: fmt, clippy `-D warnings`, `check-deps`,
  `cargo test -p purge-broker -p purge-exec -p purge-rpc -p purge-engine`, `gen-dto --check`,
  `dotnet build ui\Purge.App -c Release` (0 warnings), `dotnet test ui\Purge.Client.Tests` (UI tests build the
  Rust pipe harness with `cargo`, so cargo must be on PATH), push, then build the Inno setup and hand it over.

### Still open from M3-R2 (DONE 2026-11-22; the M2 residual is reworked on `r2-m2-inline`, pending re-review, see the top section)
- Point 2 phrasing: reword B4 in the design to "changes outside Purge's store" (recovery with nothing to change
  runs without a dialog).
- N1-N9 nits (docs/reviews/m3/r2-review.md, Notes).
- Write a "Fixes" section into `docs/reviews/m3/r2-review.md` (r1 has one) and add DECISIONS rows for the R2
  rulings (M1 consent, B1 machine env, M2 interpreters, M3 observed rules, S2 program-wide spend, S5 alerts,
  S7 subsystem, point 3 declined purge, point 6).
- The `freeze-plan`/`bind` performance note: `nested_candidates` is O(items x document) per selected item (M4
  fix). Fine so far; index it if a large consent view is ever slow.

### Not run (unchanged backlog)
- Full `cargo xtask replay-all` on the frozen rig runs (~47 min, needs `PURGE_RUNS_DIR`), and the two ignored
  xtask replay tests. Unelevated `xtask ci` (`schtasks /run /tn PurgeCiUnelev`, log
  `C:\purge-build\ci-unelev-laptop.log`) - not run since e285d26 (M3 waves 2+).
- Bench timings: warm run needs an idle host; cold series needs the user's 5 reboots
  (`cargo xtask bench-launch --cold --reset --purge out\purge`, then plain `--cold` x4).
- VM: real elevated broker start (exit codes 20-27), UAC + server check, both uninstall routes end to end, the
  four+one consent dialogs on the secure desktop (arming, paging, footer code, foreground), `allow_irreversible`
  packages, real Restart Manager/System Restore, crash-at-every-step, `undo_fidelity` over the pipe, medium-route
  VS Code, a real failed uninstaller 1603/3010, installer/uninstaller of the Inno setup.
- `xtask ui-strings` (needs `PURGE_UT_STRINGS` + the reference file, not on this laptop).

### Harness notes from this session
- Sonnet here is `anthropic/claude-sonnet-5-5`; the reviewer is `anthropic/claude-fable-5-2#medium`. Look model
  ids up, do not type them from memory.
- Writers sometimes run commands in the MAIN checkout (M3-EXEC reverted its own; the M1 writer did not). Check
  `git status` in the main checkout after every writer, not only in the worktree.
- `cargo`/`dotnet` builds: `CARGO_INCREMENTAL=0`, `TEMP=TMP=C:\purge-build\tmp`. Each worktree's target is
  6-12 GB; delete merged worktrees' `target/`. ~40 GB free at pause.
- Known cosmetic: 3 unused-import/dead-code warnings in `purge-exec/src/act_service.rs` show only in the test
  profile; `clippy -D warnings` is clean.
- Writer notes (read before touching a package): `docs/m3-notes/{broker-core,consent,broker-flow,exec,undo,
  ui-client,ui-s2}.md`. Reviews: `docs/reviews/m3/{r1,r2}-review.md`.

## RESUMED 2026-11-21 night (OpenCode, Opus coordinating, Flash/Sonnet writers). Goal: reach wave 5 fast.
- M3-R1 DONE: review docs/reviews/m3/r1-review.md (B0 M2 S9 N11, Fixes section), fixes merged bfde762. Deferred:
  S1 + S7 rest -> M3-BROKER-CORE; S8 (release provenance, design decision). No "pending review" DECISIONS rows left.
- Disk: C: ran full (parallel worktree targets ~10 GB each). Use CARGO_INCREMENTAL=0; delete merged worktrees' target/.
- Wave 3 merged into baseline (946b915): M3-ICONS, M3-UI-SHELL, M3-GEN-DTO (hand-written C# DTOs, NJsonSchema
  rejected; gen-dto output LF via .gitattributes), M3-STDIO, M3-RUNNER. Merged-tree fmt/clippy/engine tests ok.
  Notes: STDIO warms the inventory before the first request (+~1.5 s to engine.hello in debug; check against the
  launch gate in release). RUNNER level refusal uses error kind `runtime` (no dedicated kind). Unwired: worktree
  `m3-wire` (Flash, running) plugs icons + uninstall handlers into stdio.rs.
- Also merged: M3-WIRE (icons/uninstall served by stdio), M3-BROKER-CORE 2ec05f2 (notes docs/m3-notes/broker-core.md;
  account-only mismatch gets no answer, console-window flash open), M3-UI-CLIENT 1c27e6b (docs/m3-notes/ui-client.md),
  M3-ENGINE-OUT 3d183bd (user waived the "after BL-GATE" rule; frozen_plans.rs replays 18 M1b scans, hashes equal).
- Wave 4 merged: M3-CONSENT (docs/m3-notes/consent.md), M3-UI-S1 (real Programs page), m3-list-first (list reply
  before patches; hello 13-18 ms release), M3-BROKER-FLOW ae35e06 (docs/m3-notes/broker-flow.md). Wave 5: M3-PURGE
  merged 3b4b877 (broker module, wired by EXEC).
- Running (worktrees of the same name): M3-UNDO + M3-EXEC (Sonnet 5.5; EXEC also wires purge + ObservedParams
  outcome + Plan::release + irreversible ack), M3-UI-S2 + M3-UI-S3 (Flash; they may both define LeftoversRequest).
  Not yet run: full replay-all (frozen rig runs, ~47 min), unelevated ci. UI test
  ProgramsPageTests.Patches_after_the_reply... failed once under load (flaky?), passes 3/3 idle.
- VM backlog: broker real elevation + start test, UI-CLIENT runas/server check, RUNNER medium VS Code, TASKDLG/S6.
- M3-BENCH reviewed + fixed (0202a25), merged into baseline 2a6aa97. Timings NOT taken: warm run needs an idle
  host (later), cold series needs 5 user reboots (`cargo xtask bench-launch --cold [--reset] --purge out\purge`).
- Wave 3 started early, in parallel (unelevated ci deferred to merge time): worktrees `m3-stdio` (Flash),
  `m3-icons` (Flash), `m3-ui-shell` (Sonnet), all from 2a6aa97. Waiting: M3-BROKER-CORE and M3-GEN-DTO (after the R1
  fixes: pipe binding S1, CandidateRef M2), M3-RUNNER (next free slot), M3-ENGINE-OUT (rule: after BL-GATE).

## PAUSED 2026-11-21 ~21:00 (third pause, user asked for a handoff). Nothing pushed this session.
State: `baseline` holds M3 waves 1-2 except M3-BENCH, plus BL-RESIDUE. No VM running, no build running.
- Merged (local only): M3-S0 a9aa940, M3-UI-IMPORT, M3-RIG-UAC 77ded10, M3-WIN-TASKDLG 9404a2a, M3-WIN-PIPE
  2e6c265, M3-WIN-PRIV, M3-RPC, M3-HARDEN 9d2bfe4, M3-DEPS (merge after 4bdff2b; check-deps 5/5 ok), BL-RESIDUE
  (bbd38a0, local-baseline wave 6). DECISIONS: 7 coordinator rows for the writer choices (5b579d0), the 5 security
  rows say "pending review M3-R1"; M3-DEPS 4e row written by its writer.
- Writer digest for the review and DECISIONS: `docs/m3-notes/wave2-writers.md` (choices, binding notes for
  M3-STDIO/M3-BROKER-CORE, what M3-R1 should attack).
- Elevated VM unit run PASSED (32/32, Windows-native route: host-built test exes run by the elevated rig agent;
  vm/win-unit.sh is Linux-host only): R8b M1 owner restore fixed. Evidence E:\purge-build\gate-evidence\m3-win-elev.
- RIG-UAC: medium->high dialog 0/9, high control 4/4, secure desktop answered from the host (Alt+Y/Alt+N
  scancodes); vm/truth/m3-rig-uac.md, snapshot `m3-uac-on`.
- Checks on the merged tree: fmt, workspace clippy -D warnings, check-deps, tests of purge-win/broker/exec. Full
  unelevated `xtask ci` NOT run since 02f8830.
- Open from UI-IMPORT: `xtask ui-strings` not run (reference file not on the laptop; needs PURGE_UT_STRINGS).

### Stopped mid-work (resume these first)
1. **Fable review M3-R1** (critical, wave 2): stopped before writing anything. Restart it: reviewer Fable medium,
   output docs/reviews/m3/r1-review.md, scope `git diff 02f8830..baseline` for purge-rpc, check_deps.rs,
   purge-win pipe/token/process/privilege/reg_write/secure/known_folders/eventlog/taskdialog, broker start.rs/
   main.rs/build.rs/manifest, engine main.rs/pipeline(.rs, /baseline.rs), purge-exec act_service.rs; attacks in
   M3_DESIGN.json review_points M3-R1; also rule on the writer choices. Then fix B/S, confirm the 5 pending
   DECISIONS rows.
2. **M3-BENCH** (Sonnet): uncommitted work in worktree `.claude/worktrees/agent-a0d483433fd069807` (based on
   4bdff2b): xtask bench_launch.rs + main.rs, ui/bench/ (BareWinUI), LaunchMarkers.cs, MainWindow, Program.cs,
   ProgramsView, FakeEngineClient. Its last words: "Fixed. Run the bench." -> builds were done, no timings taken.
   Review the diff, run the bench on an idle host (cold-boot runs need the user's 5 laptop reboots: pending),
   commit, merge.
3. Then unelevated ci (`schtasks /run /tn PurgeCiUnelev`, log C:\purge-build\ci-unelev-laptop.log), then M3 wave 3
   (M3-STDIO, M3-ICONS, M3-RUNNER, M3-BROKER-CORE, M3-GEN-DTO, M3-ENGINE-OUT, M3-UI-SHELL).

### Owners needed (from writer reports)
- HARDEN: purge-exec `StorageRoots::installed()` still env-dependent (rig CLI path); `/DEPENDENTLOADFLAG:0x800` in
  bins/purge-broker/build.rs (allowed by rule 4f); event-log source "Purge" registration in install.ps1; elevated
  tests need PURGE_TEST_BROKER_EXE/ENGINE_EXE/OTHER_VOLUME_DIR; T6/T7 on a VM.
- TASKDLG: "opens on the cursor's monitor" (M3-CONSENT); paging/gating/close untested on a VM.
- BL-GATE (wave 6 rest) still open, needs a VM.

### Harness notes from this session
- Agent worktrees (`isolation: worktree`) are cut from origin HEAD (m1b c8370f9), not `baseline`: brief every
  writer to `git reset --hard baseline` first.
- Parallel writers touching crates/purge-win/Cargo.toml conflict on the one-line windows-sys feature list:
  resolve by union.
- Don't pipe a check into `tail` before `&& git commit` (exit code lost).

## Done
- Waves 1-4 merged: BL-WIN-SXS, BL-WIN-OFFREG, BL-MANIFEST, BL-SOURCES, BL-BUILD, BL-RIG-DIFF, BL-MEASURE
  (gate M on both VMs and the host, `vm/rig-baseline-local.ps1`), BL-VIEW, BL-POLICY.
- Gate M closed: review `docs/reviews/baseline/bl-rm-review.md` (no B); `kb/baselines/view.json` marks 7 areas
  merged, none local. Reports in `vm/truth/baseline-local/`; evidence `E:\purge-build\gate-evidence\bl-gate-m\`.
- **Presence-only** (bd8ef2e, W2 pre-estimate 1.4 %, `docs/reviews/baseline/w2-preestimate.md`): no offer on
  inferred absence; the cap (BaselineInferred, P-BL-1) stays as defence in depth.
- Wave 5 merged into `baseline`:
  - BL-FRAMEWORK 4cfa5db, merge d530862. Every baseline use classified (xtask `baseline-sites`, 65 rows), one
    `purge_model::BaselineTrust`, seal, L5 tests per scanner. Golden `cls_assoc_vscode_merged.txt` not made
    (presence-only: a merged view is checked against the no-baseline golden).
  - BL-CACHE a3058f9, merged with BL-FRAMEWORK in a3d39a3, merge e285d26. Per-source cache of the hashed sets under
    `%ProgramData%\Purge\baseline`, admin-only directory rule (junction refused), elevated: shipped dir, exact file
    and `view.json` must be admin-only writable; pipeline passes the real view; policy trust
    `for_policy(ctx.absence_trust(), fp.harvest_trust(...))`; engine.hello reports baseline_trust. Measured
    (release, unelevated, laptop): build peak 244.8 MB (budget 300), view load 0.30-0.33 s cached, 1.24 s first
    load (budget 1.5 s). Not measured: elevated, cold file cache.
  - Unelevated `xtask ci` passed at e285d26 (`C:\purge-build\ci-unelev-laptop.log`, EXIT 0 14:23).
- BL-R1 Fable review: `docs/reviews/baseline/bl-r1-review.md`, no B; 3 M, 7 S, 11 N. Confirmed: no A site reaches
  an offer below Exact, no plant/poison path for a standard user, no false Exact, `is_admin_only_writable` holds.

## PAUSED 2026-11-21 late (second pause). Nothing pushed this session.
## - BL-R1 DONE: `bl-r1-fixes` merged into `baseline` (2f64563, local only, not pushed). Final suite passed in the
##   worktree: fmt, the 3 clippy runs, check-deps, no-new-walks, scanner-coverage, baseline-sites, `cargo test
##   --workspace` (3 act_fs/fs_write DACL tests fail only with the profile Temp, which has no AI flag; pass with an
##   AI temp dir, as `C:\purge-build\ci-unelev.cmd` already does). Frozen-run L5 test PASSED end to end (all 4 runs,
##   2819 s). DECISIONS BL-R1 row confirmed (84df1ed). Unelevated ci started at 2f64563: result in
##   `C:\purge-build\ci-unelev-laptop.log` : all steps passed, EXIT 0 17:43.
## - M3: user answered open questions 1-6 (028cab7 on `m3-design`, M3_DESIGN.md section 7 + DECISIONS row).
##   Reading notes by Flash in `docs/m3-notes/reading-{a,b}.md` (11eeac5) cover section 9's reading list except
##   the WinAppSDK 2.6.x restore check. Next: Fable finishes M3_DESIGN.{md,json} from the draft + notes, then Q7.
## - Pushed 2026-11-21: `baseline` adc5d82, `bl-r1-fixes` 84df1ed, `m3-design` 3c0d030.
## - M3 DESIGN DONE (Fable): `m3-design` cc3beae (local, not pushed): M3_DESIGN.{md,json} complete, 33 packages in
##   8 waves, Fable reviews after waves 2, 5, 7; mockup deltas in section 7a; 8 coordinator DECISIONS rows (Q7: UI
##   starts from the 0d9c008 `ui/` tree by copy). WinAppSDK 2.6.5 restores with .NET SDK 10.0.404. Next: merge
##   `m3-design`, then wave 1. Later user items: 5 laptop reboots for the cold-boot bench; code-signing cert.

## Paused: BL-R1 fixes (critical, Fable), branch `bl-r1-fixes` at 081f507 (pushed, not merged)
- 10 commits on e285d26; 081f507 adds the review's Disposition section, a DECISIONS row for what the fixes decided
  (marked "to be confirmed by the coordinator": confirm or edit it), and a fix to the ignored frozen-run test.
  M1 also added a `hello` CLI verb. Rig self-test 422/0 (one known timing flake, `Wait-DefenderIdle`, not ours).
- **Not run yet**: the whole final suite (below). Per-crate tests passed at each commit; purge-scan ran in full
  only at S2. The ignored frozen-run L5 test (`l5_holds_for_the_frozen_runs_with_an_injected_view`) has never
  passed end to end: vscode and git held, firefox failed on a comparison artifact that 081f507 fixes, npp not
  reached. Run it alone (~12+ min, no other xtask build at the same time):
  `$env:PURGE_RUNS_DIR='<repo>\vm\runs'; cargo test -p xtask l5_holds_for_the_frozen_runs -- --ignored --nocapture`.
- Deferred to BL-GATE: a purge-harvest "whole fingerprint is a subset" test (M2 suggestion).
- Commits: M3 957c1be (one
  `has_classes_hive` for regpath, guard canon, harvest source_key), M2 7c114e1 + ba949a1 (replay
  `--baseline-view merged|local` injects the view into harvest and scan; `--l5-against <no-baseline plan>`),
  M1 d645393 (rig protects its baseline tree, asserts baseline_trust from engine.hello per run; **untested on a
  VM**), S5 f094230, S2 2a8a917, S3/S7 ba07878 (L5 stated once: nothing new, no band raised, preselected subset),
  S1 2c415f4 (docs), S6 c588741 (baseline-sites reads past test items, every crate, classifies view methods).
- To finish: in the worktree run `cargo test --workspace --no-fail-fast`, clippy -D warnings
  (workspace, `-p purge-mcp`, `-p purge-engine -p purge-exec --features purge-engine/rig-exec,purge-exec/test-support`),
  `cargo fmt --all --check`, xtask check-deps, no-new-walks, scanner-coverage, baseline-sites. Then on `baseline`:
  delete the untracked copy `docs/reviews/baseline/bl-r1-review.md` (the branch has it), `git merge --no-ff
  bl-r1-fixes`, unelevated ci (`schtasks /run /tn PurgeCiUnelev`), push.
- Deferred to milestone M3 (in the review's Disposition): S4 (directory rule cannot tell another machine's volume;
  `PURGE_KB_DIR`/ProgramData taken from env) and the N notes (N5 fingerprints made at medium integrity, N6
  unelevated gets no local cache under the install.ps1 root).

## Started in parallel: milestone M3 (UI + broker), user's request 2026-11-21
- Design first (Fable): worktree `.claude/worktrees/m3-design`, branch `m3-design`, delivering
  `docs/M3_DESIGN.{md,json}` in the BASELINE_LOCAL/M2 design schema, plus DECISIONS rows and open user questions.
- Paused at draft 695bd7e: only `docs/M3_DESIGN.md` exists. Done: code state (`purge-rpc` holds only EngineHello;
  `--stdio`/`--broker` are stubs exiting 1; check-deps rule 4 forbids the executor in release), inherited
  requirements table, draft architecture (medium vs elevated, ids only over the pipe, consent and execution on the
  same in-memory bound plan), draft broker threat table, package names. TODO (marked in the doc): scope, RPC
  additions, launch gates + S1 skeleton bench, screens S1-S4/S7, consent dialog content, tests (VM rig, UAC-on),
  gate criteria, risks, waves/review points/cut_or_move, `M3_DESIGN.json`, DECISIONS rows. Not yet read: the
  M2_DESIGN.json schema, install.ps1, xtask ui-strings/ci, the stopgap UI branches' content; WinAppSDK 2.6.x restore
  not checked.
- Open user questions (ask before finishing the design):
  1. Per-user apps: BL-R1 says do not trust a harvest made at medium integrity, the plan says per-user apps need
     no UAC. Prompt UAC for per-user uninstalls too, or cap medium-made evidence below Safe/preselection?
  2. The broker needs the executor, ending the 2026-11-15 "no executor in release" rule: one executable, or a
     separate broker binary so the medium engine stays executor-free?
  3. Standard-user accounts (over-the-shoulder elevation): support in M3, or refuse clearly and defer to M4?
  4. Code-signing route (decides whether the broker's caller check verifies a signature or only a path).
  5. Closing apps / restarting Explorer / boot-time ops (M2 never does them): enable with consent in M3, or
     report-only?
  6. `SeRestorePrivilege` for undo's owner restore (R8b M1): allow for that one step, or keep the known limit?
  7. Reuse of the stopgap UI (not assessed yet).
  Inputs: ENGINE_PLAN 3, 7, 9, 11; M2_GATE 8; M1B_GATE (R8b M1); HANDOFF-m1b M3 notes; BL-R1 S4/N5/N6; prior-art
  stopgap shell on `origin/worktree-agent-a7c285be2b9791f54` (0d9c008).
- Toolchain: .NET SDK 10.0.404 is installed at `C:\Program Files\dotnet` but not on PATH in agent shells.
- BL-GATE (wave 6) is not a prerequisite for M3 code that does not touch the baseline; the M3 gate runs after it.

## Next
1. Wave 6: BL-RESIDUE (medium), BL-GATE (R3 replay with `--baseline-view` + `--l5-against`, R4 campaign with the
   exact baseline hidden; S1-S5, W1-W5; writes `docs/BASELINE_LOCAL_GATE.md`). First run of the rig must confirm M1
   (baseline_trust Exact on exact runs). Before BL-GATE: drift run or R5 proxy list (BL-RM S3), settled
   first-read W4 measure (S7).
2. Open: R5 S4 had 24 of 168 inbox packages fail to parse (look at appx.rs). Slow test: `reg`
   `hostile::no_scanner_offers_a_value_that_holds_foreign_text_as_safe` ~400 s in a debug-info-off build.
3. Then milestone M3 (UI + broker); R8b M1 owner limit, UAC-on broker test, BL-R1 S4/N5/N6 belong there.

## Environment notes
- Build with `CARGO_BUILD_JOBS=2`, `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_INCREMENTAL=0`: parallel debug target
  dirs fill C:. `E:\purge-build` is a junction to `C:\purge-build` (no extra space; building under it makes the
  engine tests fail with "link or junction"). Delete a finished worktree's `target/`.
- Workspace tests need `TEMP=TMP=C:\purge-build\tmp` (profile Temp DACL lacks AI; 2 act_fs tests), as
  `C:\purge-build\ci-unelev.cmd` does.
- `xtask ui-strings` is skipped unless `PURGE_UT_STRINGS` is set.
- User's name scrubbed from the tracked tree (f5e6602, ba920c8); git history still has it (rewrite only if the
  user asks).

## Rules
One VM at a time, VMPWFILE only via env, never DietPi/clones/UT, critical work is done and reviewed by Fable
(non-critical may go to a cheaper model), commit locally, push when the user asks (asked 2026-11-21: commit and
push, keep this handoff current).
