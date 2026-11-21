# Local baseline handoff (paused 2026-11-21 evening)

Branch `baseline`, pushed to `origin/baseline`. Design `docs/BASELINE_LOCAL_DESIGN.{md,json}`; every decision of
this work is a 2026-11-21 row in `docs/DECISIONS.md` (Post-M1b), mostly "(coordinator)". This file is kept current
so the work can be continued from any harness: read it, then `git log --oneline -15` and `git worktree list`.


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
- DeepSeek Flash jobs time out at 900 s server-side; the edits survive in the worktree, continue with `session`.
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
