# Local baseline handoff (paused 2026-11-21 ~12:35)

Branch `baseline` (local, not pushed), HEAD ba920c8. Unelevated `xtask ci` passes at ba920c8
(log `C:\purge-build\ci-unelev-laptop-ba920c8-pass.log`). Design `docs/BASELINE_LOCAL_DESIGN.{md,json}`;
every decision of this work is a 2026-11-21 row in `docs/DECISIONS.md` (Post-M1b), mostly "(coordinator)".

## Done
- Waves 1-4 merged: BL-WIN-SXS, BL-WIN-OFFREG, BL-MANIFEST, BL-SOURCES, BL-BUILD, BL-RIG-DIFF, BL-MEASURE
  (gate M on both VMs and the host, `vm/rig-baseline-local.ps1`), BL-VIEW, BL-POLICY.
- Gate M closed: review `docs/reviews/baseline/bl-rm-review.md` (no B); `kb/baselines/view.json` marks 7 areas
  merged, none local; W1 and W4 restated. Reports in `vm/truth/baseline-local/`; evidence
  `E:\purge-build\gate-evidence\bl-gate-m\`.
- **Presence-only** (bd8ef2e, W2 pre-estimate 1.4 %, `docs/reviews/baseline/w2-preestimate.md`): no offer on
  inferred absence; the cap (BaselineInferred, P-BL-1) stays as defence in depth.
- Scan-path fix 59ae960 (regpath: `.DEFAULT`, S-1-5-18/19/20 keep `Software\Classes`), not yet reviewed.
- User's name scrubbed from the tracked tree (f5e6602, ba920c8); git history still has it (force push only if
  the user asks).

## Interrupted (wave 5), uncommitted work kept in worktrees
- BL-FRAMEWORK (critical, Fable): `.claude/worktrees/agent-af7257edcb63317ff` (66 changed files, uncommitted;
  was adding the L5 tests). Brief: presence-only, A sites below Exact behave as values-only; unify the two
  `BaselineTrust` enums onto `purge_model::BaselineTrust`; L3 goldens unchanged; owns purge-scan/harvest/testkit,
  xtask baseline-sites.
- BL-CACHE (critical, Fable): `.claude/worktrees/agent-acb36468a3fd34755` (12 changed files, uncommitted; was
  adding cache tests). Brief: derived `HashedSets` cache bound to the text file's sha256 (view load <= 1.5 s),
  cache parts per source (S4 update keeps S1), S3 live, reduce peak memory (R5 298.7 MB of 300), owns
  pipeline.rs, Settings, hello, `DecideCtx::baseline_trust = BaselineTrust::for_policy(...)`.
- To resume: finish each in its worktree (review the diff, run its tests), commit, merge into `baseline`
  (BL-CACHE owns pipeline.rs; reconcile), unelevated ci (`schtasks /run /tn PurgeCiUnelev`, log
  `C:\purge-build\ci-unelev-laptop.log`).

## Next
1. Fable review BL-R1 (design review_points; include regpath 59ae960).
2. Wave 6: BL-RESIDUE (medium), BL-GATE (R3 replay, R4 campaign with the exact baseline hidden; S1-S5, W1-W5;
   writes `docs/BASELINE_LOCAL_GATE.md`). Before BL-GATE: drift run or R5 proxy list (BL-RM S3), settled
   first-read W4 measure (S7).
3. Open: R5 S4 had 24 of 168 inbox packages fail to parse (look at appx.rs).
4. Then M3 (UI + broker); R8b M1 owner limit and UAC-on broker test belong there.

## Rules
CARGO_BUILD_JOBS=2-4, one VM at a time, VMPWFILE only via env, never DietPi/clones/UT, critical work gets a Fable
review, commit locally, push only when the user asks.
