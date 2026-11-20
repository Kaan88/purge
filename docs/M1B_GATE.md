# M1b gate report (scan integrity and typed actions)

- Dates: scan gate 2026-11-19, executor gate 2026-11-20/21.
- Procedure: `docs/M1B_DESIGN.json` (`gate_procedure`, `gate_criteria`), summary in `docs/M1B_DESIGN.md` "Gate";
  rig `vm/RIG.md`; scorers `vm/truth/m1b.sh` (scan) and `vm/truth/m1b-exec.sh` (executor).
- Decisions, accepted limits: `docs/DECISIONS.md`, section "M1b". Reviews: `docs/reviews/m1b/`.
- Rig host: the laptop (`docs/MIGRATION-laptop.md`, `docs/HANDOFF-m1b.md`). VMs Inbound-Win11-Test (Windows 11 LTSC
  26100, snapshots `m1b`/`m2-base`) and Purge-CleanPro (Windows 11 Pro 26340).
- Branch `m1b`. Scan gate bound to commit `7e885aa` (release engine sha256 `23529600…`); executor gate bound to commit
  `3f95da7` (rig-exec engine sha256 `52a8ee29…`).

## 1. Verdict

**M1b gate: PASS.**

- Scan gate (G1 to G4, G7, G8): **153 of 153 criteria rows pass**, `m1b.sh` verdict gate, nothing failed
  (`vm/truth/m1b-score.json`, 2026-11-19T11:17:51+03:00). 26 of these rows pass empty, as the design allows: K4
  `precision_safe` is undefined (no Safe item) in 16 rows and K5 is n/a (no protected truth item) in 10. On the VM sets
  only 7-Zip has a Safe item, so K4 precision rests on 7-Zip there and on the vscode, git, firefox and 7-Zip replays.
- G0 (K15, release build links no executor or write path): `cargo xtask check-deps` ok inside the unelevated
  `xtask ci` runs at 7e885aa (`E:\purge-build\ci-unelev-laptop-7e885aa-pass.log`) and at 3f95da7 (2026-11-20 23:41,
  copied to `m1b-gate7\ci-unelev-3f95da7.log`; the log records the file time, not the commit). K15 is in neither
  scorer.
- Executor gate (G5, G6): **PASS, failing none, missing none** (`vm/truth/m1b-exec-score.json`,
  2026-11-20T22:34:26 UTC). BIND, K10, K11, K12, K13, E1 all pass.

Evidence: scan `E:\purge-build\gate-evidence\m1b-gate6\final\`, executor `E:\purge-build\gate-evidence\m1b-gate7\`
(step logs, score log, score JSON, runs).

## 2. Scan gate (commit 7e885aa, engine 23529600)

| Step | Criteria | Result | Key numbers |
|---|---|---|---|
| G1 M1a replay | K4, K7, K16 | pass | vscode, git, firefox, npp, 7zip: danger_listed 0, precision_safe 100 % where defined; 7-Zip `HKU\<sid>\Software\7-Zip` listed; replay diff 3 rows, unexplained 0, promotions 0 |
| G2 rig-base (clean) | RUN, SANITY, K1, K3 to K8 | pass | 8 apps (7zip, python, python312-with-313, python313-with-312, node, vcredist, powershell, temurin). danger_offered 0 (danger_kept named below), danger_preselected 0, userdata_preselected 0, band mismatches 0; protected_correct 100 % (python 29 Launcher items, py312/313 pairs 42 and 44, powershell 2); 7-Zip MSI root found from components, `HKU\<sid>\Software\7-Zip` offered; python launcher suggestion `ReportOnly` with one notice, no notice elsewhere |
| G3 dirty-base | RUN, K2 to K6, K8 | pass | 7 apps (node dropped from G3, user ruling 2026-11-18). danger_blocking 0, preselection 0, protected_correct 100 % |
| G4 traps | K9 | pass | rig-base and dirty-base: 26 cases each, escapes 0, missed owned 0, failed 0, unplanted 0 |
| G8 Purge-CleanPro | RUN, K1, K3 to K5, K8, K9 | pass | 7zip, python, vcredist clean; 26 traps, escapes 0 |
| G7 budgets (K14) | K14 | pass | 20 runs, 0 problems; one reference walk per scan; added scan +1.08 s warm / +1.57 s cold (limits 2.5 / 6.5); added harvest +1.01 s warm / +1.19 s cold; ownership.components 0.245 s; tables 0.254 s cold, 0.139 s warm; like for like |
| BIND | | pass | one engine, one commit, committed traps and labels, identical rig inputs |

**danger_kept (K1).** The only kept danger item is the `bam\State\UserSettings` value, listed Blocked with blocker
`DenyListed` (report only), in clean python, python312-with-313, python313-with-312 and vcredist, and dirty vcredist.

**G7 on the laptop (user ruling 2026-11-19).** The desktop was busy, then offline, so G7 ran on the laptop and is judged
relative to the desktop CPU: the laptop's own numbers already pass every K14 limit and a faster CPU only lowers them, so
no scaling is applied. Program: ATK Package `HKLM|32|{AB5C933E-5C7D-4D30-B314-9C83A49B94BE}` instead of the desktop's
Virtual Desktop Service, which the laptop does not have. ATK and Intel Wireless Bluetooth were the only laptop MSI apps
with one root in both engines and no co-product. ATK is a lighter program than the desktop's, so the K14 numbers are
not comparable one to one with the desktop precheck (`HANDOFF-m1b.md`: +1.80 s scan, +1.86 s harvest, components
1.22 s there). The ruling covers CPU speed, not host size: the laptop has 205 inventory entries and 107 MSI packages,
against the design's 591-program host. At design scale K14 rests on that desktop precheck (at 8e1a1d2, within every
limit), which is not a gate-bound run.

**Why the whole scan campaign is laptop-only.** Campaign 4 mixed desktop and laptop runs and failed BIND: two engine
builds, two commits, and CRLF (laptop) against LF (desktop) working-tree bytes in the rig inputs. G1 to G4a were rerun
on the laptop, so every scan run is bound to 7e885aa.

## 3. Executor gate (commit 3f95da7, rig-exec engine 52a8ee29)

| Step | Run | Result | Time |
|---|---|---|---|
| elevated tests (E1, scored in G6) | `m1b-x-elevated` | pass on the retry (section 5) | |
| G5 fidelity (K10, K11) | `m1b-x-fidelity` | ok | 235 s |
| G5 act-time traps (K10, K12) | `m1b-x-traps` | ok | 233 s |
| G5 undo traps (K12) | `m1b-x-undo-traps` | ok | 139 s |
| G6 crash, hard power-off (K13; its execdiffs count in K10) | `m1b-x-crash -HardPowerOff` | ok | 5492 s |

| Criterion | Result | Key numbers |
|---|---|---|
| BIND | pass | 5 runs, one commit; the 4 VM runs one engine (`52a8ee29`, staged = installed; the elevated run binds commit and cases, no test-binary hash), one commit, source clean, cases sha256 `672e6991…`, ambient set `vm/truth/m1b-exec-ambient.json` sha256 `49214ff7…` declared = guest in every VM run, 6 null runs per mode, no bad run |
| K10 collateral | pass | fidelity and traps execdiffs: collateral 0, guard escapes 0, unexplained 0, missing effects 0, changed-not-done 0; 44 crash execdiffs, none failing |
| K11 fidelity | pass | 10 variants. Full undo exact for svc-full, svc-localservice, task-simple, task-hidden-two, task-com, task-sddl, fw-program, fw-addresses, fw-profile (minimum 2 / 4 / 3 met). fw-service refused (Blocked) and unchanged. Rows: DeleteService 2 ops 28 objects, DeleteTask 4 ops 16 objects, DeleteFirewallRule 3 ops 6 objects, differing 0, 100 % |
| K12 traps | pass | act time (the design text says 6 of 6 skipped; since the R4 S5 fix the same-name case expects the twin untouched and the base rule deleted as planned): 5 of 5 skipped (svc-running `InUse`, svc-dependent `HasDependents`, svc-repoint / task-edit / fw-edit `ChangedSinceScan`) + 1 of 1 same-name firewall twin untouched, nothing deleted, exec exit 10. Undo: 4 of 4 conflicts (impostor service and task `ObjectExists`, tampered definition `BackupTampered`, missing definition `BackupMissing`), nothing overwritten, undo exit 11 |
| K13 crash | pass | 74 planned rows, 74 run, none unreached, none failing; every declared fault point in the gate; hard power-off 5 rounds per kind (service, task, firewall), 15 of 15 consistent, all cut mid-run at distinct points |
| E1 elevated tests | pass | admin; purge-win scm 12, firewall 12, taskschd 11; purge-exec act_service 3, act_task 1, act_firewall 1 |

## 4. How we got there

1. **Reviews.** R1, R2a, R2b, R3a, R3b, R4, R4b, R4c, R4d, R5, R5b, R6 before the gate; R8 and R8b on the gate fixes
   (all Fable, `docs/reviews/m1b/`). Findings fixed or recorded as limits.
2. **Scan campaigns.** Round at ee43fa2: 133/153 (engine gaps fixed: Burn python-launcher suggestion, co-product index
   reuse; rig and scorer fixes). Round at c388dd1: 148/153, only clean/temurin failed from a Defender signature update
   inside the capture window (fixed: Defender noise rules, the guest waits for Defender before snap 0, RUN checks the
   signature versions). Campaign 4 paused for the laptop migration, then BIND failed on the mixed hosts (section 2).
   Final laptop campaign at 7e885aa: 153/153.
3. **First executor campaign (rig-exec engine 45fbbee0).** BIND, K12, E1 pass; K10, K11, K13 fail. Causes:
   - engine: the service undo re-created a subkey without the recorded descriptor (no `D:AI`), so svc-full undo ended
     in a Conflict and 25 service crash rows failed;
   - rig: the task GUID kept its trailing NUL, rigtool snap truncated on it, and no task crash round ran;
   - rig gap for K10: restore point / VSS and firewall WMI side effects and Windows churn had no rules and no M1b
     exec ambient set.
4. **Fix rounds.** Engine f000afd, 6fd053a (write-back puts the recorded descriptor on a re-created subkey, converges
   on an existing key, writes all it can, names an owner it could not assign). Rig c85849d, eb17c9b, ad91cde, 5b13a6e,
   3f95da7: the task Id NUL trimmed and checked; engine side-effect rules; one exec window for gate and null runs
   (R8 B1: the traps null window lacked the after-exec WMI reads); null mode `m1b-x-null` and the committed ambient set
   (12 null runs); BIND binds the ambient set; hive transaction log rule (below); E1 names. Fable reviews R8, R8b.
   Before the rerun: unelevated `xtask ci` pass at 3f95da7, and a host replay of both failed execdiffs with the new
   ambient set came back ok.
5. **Executor rerun at 3f95da7:** pass (section 3).

## 5. Rulings, limits and notes

- **Hive transaction logs (user ruling 2026-11-20).** After a restore point, a loaded user hive's transaction log
  (`<profile>\ntuser.dat.LOG1/LOG2`, `<profile>\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1/LOG2`) changing size
  or mtime counts as the engine's side effect (`engine-rp`, rigtool `is_user_hive_log`). It applies only when the run's
  restore point is `Created`, and never to a removal. The VSS registry writer flushes the loaded hives; no null run has
  these records. Unit test plus a negative control in `vm/rigtool/tests/m1b.rs` (collateral without a restore point).
- **Known limit, R8b M1 (user ok 2026-11-20), revisit in M3 with the broker.** A resumed service undo (after an
  interrupted attempt) leaves the creator as owner of a re-created subkey whose DACL grants no WRITE_OWNER. The outcome
  is `Restored` with a note naming the owner it could not assign. An uninterrupted undo restores the owner; the exact
  check sets the owner aside. The fix belongs with privilege handling (`SeRestorePrivilege`) in the M3 broker.
- **Elevated scm test flake (coordinator ruling; the design has no retry rule).** On the first `m1b-x-elevated` run
  (start 2026-11-20 23:44:10, 3f95da7, scm exit 101), `create_then_query_equals_definition` and
  `query_own_test_service_round_trips_all_fields` got `Ok(Marked)` in their own clean-up assertion, where they asserted
  `Ok(Deleted)`: the delete stayed pending because a handle to the test service was still open, from another process
  or a sibling test thread (the log does not say which). `Marked` is a designed result the executor maps to a pending
  delete. One rerun with the same commit and test binaries passed, and that is the run the scorer bound (start
  23:49:32, log `g5-x-elevated-retry1.log`). The failed run is `vm\runs\_old\m1b-x-elevated-20261120-234932` (`_old`
  folders are named by move time), copied to `m1b-gate7\runs\m1b-x-elevated-failed-first`. Follow-up: the tests
  accept a transient `Marked` and wait for the delete.
- **Scan engine and the executor fixes (measured 2026-11-21, review R9 S6).** Two builds of each commit from one
  worktree into one target folder (`m1b-gate7\release-repro\`):
  - `cargo build --release -p purge-engine` (the shape `check-deps` checks and `install.ps1` asks for): 7e885aa and
    3f95da7 both hash `adb501b2…`; cargo recompiles nothing when switching between them. No source this build compiles
    changed.
  - `cargo build --release` (whole workspace): 7e885aa `2c852890…`, 3f95da7 `99581dfe…`, same size. The gate's scan
    engine `23529600…` (built 2026-11-19 02:31 at 045824d, same tree as 7e885aa outside `docs/`, in
    `E:\purge-build\gate`) is this shape: its size, 6 062 080 bytes, matches the workspace build, not the `-p` build
    (6 059 008). In a workspace build cargo unifies features, so purge-win is compiled with `write` (enabled by
    purge-exec) and its bytes change with 6fd053a's `reg_write.rs`.
  - Why the scan evidence stays valid: purge-engine's own source cannot call `write` items (the `-p` build compiles
    without them), and nothing else in the release-reachable crates changed, so the scan behaviour is the same at both
    commits. It is not byte-identical in the shape that was gated. Follow-up: build the gate engine with
    `-p purge-engine` (`MIGRATION-laptop.md` step 3 does not say so) and record the build shape in BIND. The original
    gate engine is kept as `m1b-gate6\final\engine\purge-engine-23529600.exe`.
- **BIND caveat:** rig inputs changed after
  7e885aa (rigtool, rig scripts, truth files), so re-scoring the scan campaign at a later commit fails BIND by
  construction. The scan verdict is bound to 7e885aa and its evidence in `m1b-gate6\final`.
- **Unelevated ci host prerequisite (laptop).** `xtask ci` needs TEMP with full-control ACEs and an auto-inherited DACL
  (`C:\purge-build\tmp`, `docs/MIGRATION-laptop.md` step 4).

## 6. Follow-ups

- scm elevated tests tolerate a transient `Marked` (section 5).
- Scorer check that the E1 test names in the cases file and in `m1b-exec.sh` match (R8b suggestion).
- Gate engine built with `-p purge-engine` and the build shape recorded in BIND (section 5).
- K15 as a scorer row; a test-binary hash in the elevated run's BIND; the K12 design text updated to 5 + 1.
- Closing review: `docs/reviews/m1b/r9-gate-review.md` (no blocker; S1 to S6 and M1 to M5 fixed here).
- M3: R8b M1 owner limit with the broker; broker elevation tested with the UAC prompt on.
- Next per the plan: local baseline (`docs/BASELINE_LOCAL_DESIGN.md`), then M3 (UI and broker).
