# Local baseline handoff (paused 2026-11-21 evening)

Branch `baseline`, pushed to `origin/baseline`. Design `docs/BASELINE_LOCAL_DESIGN.{md,json}`; every decision of
this work is a 2026-11-21 row in `docs/DECISIONS.md` (Post-M1b), mostly "(coordinator)". This file is kept current
so the work can be continued from any harness: read it, then `git log --oneline -15` and `git worktree list`.

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
## - Push of `baseline` and `m3-design` waits for the user.

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
