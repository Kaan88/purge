# M2 gate report (the executor)

- Date: 2026-11-16.
- Procedure: `docs/M2_DESIGN.json` gates G0 to G7, `vm/RIG.md` section 11, `docs/ENGINE_PLAN.md`.
- Decisions, accepted limits: `docs/DECISIONS.md`, section "M2". Reviews: `docs/reviews/m2/`.
- Engine: local branch `m2`, rig-exec build. The final gate ran on commit `70d383b` with the stricter crash gate of `3265797`.
  The head of the branch is `dea0208`.

## 1. Verdict

**M2 gate: PASS on Inbound-Win11-Test** (Windows 11 LTSC 26100, snapshot `m2-base`). All of G0 to G7 pass.
Guard escapes 0, collateral 0, undo fidelity rows failing 0, required rows missing 0, crash rows failing 0.
Source: `final-70d383b/m2-gate.md`, generated 2026-11-16T08:18:18 UTC.

The first gate run did not pass. Case p902 (hard power-off at `commit.before`) failed. It was fixed in the engine and
the gate was run again (section 3).

**Clean-Pro (Purge-CleanPro, Windows 11 Pro 26340): partial, by design of the rig.** What was run and what passed:

- G1 traps: pass. Guard escapes 0, collateral 0, the three refusals and the forged fingerprint as on Inbound.
- G2 fixture run: pass. No failing row, no required row missing, fixture checks after exec and after undo true,
  collateral 0 in the fixture group.
- G5 expiry and G6 restore point: pass.
- Engine behaviour is identical to Inbound: the same nine fidelity rows at 100%, the same app plans (firefox 20 items,
  npp 2).

What did not pass: the G2 app stage (real Firefox and Notepad++ installed, run and uninstalled, then executed) shows
collateral records. First run (`cp-`): 14. Repeat (`cp2-`): 20, of which 6 in Firefox and 14 in Notepad++. G0, G3, G4
and G7 were not run on Clean-Pro: its `m2-base` has no D: volume and only m2-traps and m2-fidelity run there
(`vm/RIG.md` section 11).

**Why this is a rig limit.** The collateral gate counts every removed or changed record that no rule authorises. The
ambient set (records Windows changes on its own) comes from null runs: the same phases with an idle wait instead of the
exec. The app stage has no null-run equivalent, because its window follows an install, a launch and an uninstall.
The records seen are Windows churn: in the repeat run, SystemTemp, a SoftwareProtectionPlatform task file, `bam` state,
TaskCache values (Firefox), and .NET NGenService root values (Notepad++). No guard escape, no missing effect in any run.
On Inbound the same stage was clean in the final run (collateral 0 for `app-firefox` and `app-npp`), but the
first Inbound gate run had 20 records of shell churn in the npp round that the repeat did not (`vm/RIG.md` 11.8). That is
the same kind of noise.

**What would close it.** An app-stage null run for each VM: install, launch and uninstall the app, wait the exec's
duration instead of executing, take snap A and snap B, and add the records to that VM's ambient set. Then run the app
stage on Clean-Pro again. This was not done in M2. M2 does not need it for the verdict, because the executor's effects
on the app stage are also covered by the fixture runs and the traps, which are clean on both VMs.

## 2. Gate table (Inbound, final run)

| Gate | Result | Key numbers |
|---|---|---|
| G0 install hardening | pass | Install exit 0; re-run exit 0 and unchanged; `-Check` exit 0. D: volume: exec exit 0, the attacker's `D:\.purge-q` renamed aside (`D:\.purge-q.rejected-20261116T073534Z`), user marker intact, not adopted, payload in the engine's own queue |
| G1 traps | pass | Guard escapes 0; collateral 0; unexplained 0; trap mismatches 0; missing effects 0. Three groups (main, race-a, race-b) all ok. Refusals: wrong confirm, tampered sidecar, reordered plan all refused with nothing changed. Forged fingerprint ok. Trap checks true after install, after exec, after expiry, final |
| G2 fidelity | pass | Failing rows 0; required rows missing 0; collateral 0; apps firefox and npp ok. Rows below |
| G3 crash | pass | 30 rows, 30 passed, 27 hit, none failing, none not hit (all 16 fault points reached). Torn journal tail and middle pass. Hard power-off: 3 rows, 3 passed (`intent.flushed`, `regdelete.mid`, `commit.before`) |
| G4 reboot | pass | Boot-time move registered and reconciled after the reboot; moved item restored by undo; a changed registration (mismatch) left alone; the retry after the mismatch skipped (`GateBlocked`, `ReparseMismatch`) |
| G5 expiry | pass | Listed; purge exit 0; store check after expiry true. Clock override `PURGE_RIG_NOW_OFFSET_DAYS=400` |
| G6 restore point | pass | First run Created, second Throttled; with System Protection off: Disabled, items done, protection re-enabled |
| G7 elevated tests | pass | Admin true; `elevated_set_security_assigns_system_owner` and `elevated_restore_puts_back_a_system_owner` pass |

G2 rows, fixture run:

| Action | ops | objects | identical | differing |
|---|---:|---:|---:|---:|
| QuarantineMove file | 2 | 2 | 2 | 0 |
| QuarantineMove dir | 5 | 22 | 22 | 0 |
| RemoveDirIfEmpty | 2 | 2 | 2 | 0 |
| DeleteKeyTree | 5 | 43 | 43 | 0 |
| DeleteKeyIfEmpty | 1 | 1 | 1 | 0 |
| DeleteValue | 6 | 6 | 6 | 0 |
| EditSegment | 3 | 3 | 3 | 0 |
| not executed | 1 | 2 | 2 | 0 |
| outside plan | 0 | 28 | 28 | 0 |

The m2-crash run made 179 engine calls over 6 stages (one reboot, three hard power-offs) and took 708 s. The log is
`final-70d383b/crash-poweroff.log`.

## 3. How we got there

1. **Reviews before the gate.** The three reviews of the packages (section 4) found 1 blocking and 22 serious findings (8, 7 and 7). They
   were fixed before the first gate run, or recorded as limits.
2. **First gate run (engine `0aa3633`).** G3 failed on one row, after rig fixes (below):
   p902, a hard power-off at `commit.before` (session `20261116T052143Z-ffce4a3f026a5a42`, evidence in
   `engine-p902-commit_before-poweroff/`). After the boot, 7 registry changes of the `nested-sequence` fixture were back
   (Windows had not written them to the hives), while the journal's `done` and `group_end` records and the resumed
   `commit` were on disk. The journal said the changes were made; the registry said they were not. Undo then ended with
   exit 11 and `KeyExists` conflicts on those keys. This is a real engine defect, not a rig fault.
3. **The fix (`6f3a6c0`).** A registry change must be on disk before the journal record that vouches for it. The writer
   flushes the hives its ops touched (`RegFlushKey`) before each `group_end`, `commit` and `aborted`, before each
   `undo_done` and `undo_conflict`, and flushes `SYSTEM` before a boot-move `done`. A registry `done` after the last
   marked `group_end` of an unfinished run counts as unconfirmed. After an unclean stop, recovery probes unconfirmed
   changes again, in op order, and makes a lost change again. Cost, measured on the host: 200 value deletes under
   `HKCU`, 2 ms without a flush, 0.6 to 0.9 s with one flush per delete, 3 ms with one flush after all 200. So at most one
   flush per hive per 64 ops in a run (row in `docs/DECISIONS.md`, 2026-11-16, "Registry durability").
4. **Review of the fix** (`durability-review.md`, section 4) found three serious problems in the new re-probe (a later op
   of the same run overtaking a change, rollback completing into a key somebody else re-created, an unmatched op keeping
   its `Done`). Fixed in `f62c7c1`: the re-probe is judged against the run's later journalled ops, runs only after a
   possible restart (system started less than 10 minutes before the journal header, or in doubt), and every
   correction is journalled as a `reconcile` `Retried` record.
5. **Gate re-run** (`g3-rerun/`, 2026-11-16T07:32 UTC): all of G0 to G7 pass, power-off rows 3 of 3.
6. **Stricter crash gate (`3265797`).** `vm/truth/m2.sh` now fails G3 unless every fault point is reached (`not_hit`
   empty) and the hard power-off rounds ran. The final run is the first with that rule.
7. **Final run** on engine `70d383b` (`final-70d383b/`): PASS, section 2.

Rig bugs found by the gate runs and fixed in the rig, not the engine (evidence folders `rig-*`, and in `final/` the
host logs of the tries):

| Evidence | Bug | Fix |
|---|---|---|
| `rig-crash-try1-hung` | The paused exec inherited the agent job's output pipe; the job waited for the engine (600 s per hit) | Shell execute without handle inheritance (`f29ef55`) |
| `rig-crash-try2-poweroff-lost-marker` | `continue.json` read back as NULs after a hard power-off | Guest flushes the run files before each power-off (`f29ef55`) |
| `rig-crash-try3-winre` | Back-to-back power cuts ended in WinRE | `bootstatuspolicy IgnoreAllFailures`, `recoveryenabled No` (`f29ef55`) |
| `rig-fidelity-try1-check-and-npp-churn` | The after-undo fixture check always reported "list values bad=1"; npp churn | Check fixed (`f29ef55`); ambient set rebuilt |
| `rig-traps-try1-expiry-refused` | The planted junction made the quarantined item hold more entries than counted, so expiry refused before any walk | Plant replaces the item's own files (`f29ef55`) |
| `settle-crash-coverage` | A snap taken while the ReadyBoot trace still ran left `ReadyBoot.etl` as collateral; two fault points never hit | Settle wait; own rows for `expiry.mid` and `bootmove.registered` (`2328e2a`) |
| `ambient-rebuild` | Explorer first-run writes at uptime about 71 s fell in the exec window | Uptime floor of 180 s; ambient set rebuilt from 6 null runs, 260 records and 28 patterns (`70d383b`) |
| `crash-try4-poweroff-rows`, `crash-try5-poweroff-rows` | Power-off rows tried while the above were fixed | Kept as evidence |
| `final/host-m2-crash-try6-cwdlock.out` | The pull of the crash run failed: a file in use | Not analysed here; the passing run is in `final-70d383b/` |

## 4. Reviews

| Review | Scope | Verdict | How its serious findings were closed |
|---|---|---|---|
| `wave1-review.md` | Guard, win, model packages (`00f3028..8a456ff`) | Accept with required changes. 1 blocking, 8 serious (S1 to S8), 8 minor | Fixed in `ec89923`, `0b0cfb1`, `7782c05`, `28691a2`. The wave 2 review checked each: B1 and S1 to S3, S6 to S8 closed; S4 and S5 closed in format only (use at act time: wave 2 S5, boot-move flush: wave 2 S6) |
| `wave2-review.md` | Store, journal, registry backup, gate (`877a3e3`) | Accept with required changes. No blocking; 7 serious (S1 to S7) | Fixed in `54824d1` (journal, store), `87dcfb5` (registry), `fa2cd8a` (gate). S5 was only partly closed, then reopened as final S5 |
| `final-review.md` | Whole executor (`efcc2b1`) | Go to the VM gate after required fixes. No blocking; 7 serious (S1 to S7), M1 to M24 | Fixed in `c8597e9`, `3bd5aaf`, `6360176`, `e0c52f8`, `ceb5999` (CLI and plan intake, registry and gate, files and undo, smoke-run fixes, volume queue). The fix-round review confirmed S1 to S7 closed, with small residues F1 and F7 |
| `fix-round-review.md` | `d2f7a63..ceb5999` | Go to the VM gate. No blocking, no serious; F1 to F11 minor | F1, F2, F3, F5 to F8, F10, F11 fixed in `0aa3633`. Open limits written to `docs/DECISIONS.md`. F4 (elevated tests run by no script) closed by G7 of this gate |
| `adoption-rule-review.md` | The adoption rule of `0aa3633` | Fine for the gate. No blocking; 1 serious (S1: the same-directory shortcut trusts the file id alone) | Fixed in `4649849`: the owner test also runs on the same-file-id branch of a move back |
| `scan-perf-review.md` | Scan speed-up `d1cfa25` | Merge after required fixes (S1, S2) | Fixed in `7edd549`: link status asked again on kept handles, a deleted key is skipped, thread start fallback, live parallel test. M1 and M2 left open (a changing registry cannot be walked atomically); neither makes the reference scan offer a wrong key |
| `durability-review.md` | The p902 fix `6f3a6c0` | Re-run the gate as is. No blocking; 3 serious (S1 to S3) in the re-probe | Fixed in `f62c7c1` (step 4 of section 3). The fix of the fix was not reviewed again; the final gate run is its test |

## 5. Second VM: Clean-Pro

- VM `Purge-CleanPro`, Windows 11 Pro 26340, snapshot `m2-base` made without a D: volume (`setup-m2-base.ps1 -NoDataDisk`).
  Runs `cp-` (2026-11-16, traps then fidelity) and `cp2-` (fidelity repeat). Engine: rig-exec release build from
  `3265797`, whose engine sources (`crates/`, `bins/`) are identical to `70d383b`, the Inbound gate engine.
- Its own ambient set, `vm/truth/m2-ambient-cleanpro.json`: 12 null runs (`cpn1` to `cpn6`, m2-traps and m2-fidelity),
  650 records, 76 patterns. One set per VM, because another Windows build churns differently.
- Results are in section 1. Run times: `cp-m2-traps` 248 s, `cp-m2-fidelity` 727 s, `cp2-m2-fidelity` 726 s.
- The `cp-gate` report lists G0, G3, G4 and G7 as FAIL only because those runs do not exist on this VM. They are not
  failures of the engine.
- Evidence: `E:\purge-build\gate-evidence\cleanpro\` (`runs\cp-gate`, `runs\cp2-gate`, host logs).

## 6. M1a re-run after the scan speed-up

The scan speed-up (`d1cfa25`, one open per key, parallel reference walk) changes the registry reference scan, which
the M1a plans depend on. The M1a campaign was run again on the new engine (`r4-`, Inbound, 7 apps and 3 null runs,
all 10 runs ok, 42 minutes). Evidence: `m1a-rerun/`.

- The offered items are unchanged: vscode 139, vscode-user 147, git 4, firefox 20, firefox-tb 14, npp 2, 7zip 0. Same
  as `vm/truth/r2`.
- Precision (Safe) is 100% in every plan that has a Safe item. Danger items: none. User data preselected: 0.
- `truth_n` moved only because Windows churn differs by day: vscode 155 to 154, vscode-user 163 to 165, git 17 to 31,
  firefox 25 to 26, firefox-tb 19 to 20, npp 28 to 34, 7zip 3 to 5. For git, 18 of the 27 missed items are Defender
  `RtSigs` files; the others are a temp file, jump lists, a prefetch file and UserAssist and jump-list values.
  recall_visible follows the truth set (vscode 89.0%, vscode-user 87.3%, git 12.9%, firefox 26.9%, firefox-tb 30.0%,
  npp 67.6%; BCU on the same truth: firefox 19.2%, npp 2.9%).
- Scan time, engine phase `engine-scan` after the uninstall: 4.5 to 9.7 s per app (npp 4.5, vscode 4.8, git 4.9,
  vscode-user 5.1, firefox-tb 5.2, 7zip 5.5, firefox 9.7). Before the speed-up it was 27.6 to 52.7 s.

## 7. Known limits

Accepted limits, all in `docs/DECISIONS.md`, section "M2" (rows dated 2026-11-15 and 2026-11-16):

- Scope: file, registry and AppX items only; service, task and firewall execute and undo wait for M1b (row 1).
- A key re-created or rewritten by someone else with exactly the validated content is accepted; only what the verified
  backup holds is deleted (row "act-time gate", final S4 and S5).
- Volumes mounted in a folder, and volume roots others could rearrange, get no quarantine; their items are skipped
  as cannot-back-up (row "Volumes mounted in a folder").
- Undo: a `MoveBack` journalled before `parent` existed, or a boot-time move whose parent could not be read, moves
  back unchecked; a key that equals its backup except for the owner counts as restored; a value restore writes into
  its key as it stands (row "Known limit (F1, F2 residue)").
- Open limits before a release: M6 (reconcile without restart evidence can end final and wrong; the gate treats an
  unconfirmed `PendingReboot` as a failed case), M8 (reconcile's move back is not write-ahead), M9
  (`PendingFileRenameOperations2` is not read), M14 residue (expiry's entry count is a budget, not a list), M18
  (retention counts from the session's `created`), M19 (the journal state machine accepts some record orders a
  writer never produces), M24 (the subtree count for the restore-point request counts direct subkeys only).
- F10: output files are never written through a link, also for `scan -o` in the M1a verbs; the build is 64-bit only.
- F11: a `done` record's detail is cut at 2,048 bytes.
- Durability: the log-order argument for files is NTFS only (durability review M5); a clock set back by more than
  10 minutes after a restart can make recovery treat a lost change as made (row "Registry durability").
- Not run on any VM in M2: service, task and firewall removal (deferred); the executor on Clean-Pro for G0, G3, G4 and G7.

## 8. What M1b and M3 inherit

- **Exit codes** of the executor verbs: the table is in `vm/RIG.md` section 11.7 (0 to 12; 12 takes precedence over 10
  and 11). The UI must read 10 (partial), 11 (undo with conflicts) and 12 (session not closed) as different outcomes.
- **Engine surface.** The release engine has no path into the executor: executor verbs exit 5 ("needs the consent
  dialog") and touch nothing. They exist only in a `rig-exec` build. The consent dialog is M3. Build releases with
  `cargo build --release -p purge-engine`, not `--workspace`.
- **M1b**: service, scheduled-task and firewall scanners emit targets that M2 already encodes as (target, `DeleteKey`);
  their execute and undo are to be written. MSI attribution (7-Zip, VS Code user install beside a system install) and
  the M1a open items are in `docs/M1A_GATE.md` section 6.
- **M3**: the broker and UI work on the sandbox dev build on branch `worktree-agent-a7c285be2b9791f54`. Expiry never
  deletes by itself: a purge needs a consent naming every item and file, and user-data items need single confirmation
  (row 2026-11-16, "Expiry never deletes automatically").
- **Rig**: to run a gate again, `vm/RIG.md` section 11 has the commands (modes m2-install, m2-traps, m2-fidelity,
  m2-crash with `-HardPowerOff`, m2-reboot, then `bash truth/m2.sh`). The ambient set is per VM and tied to `m2-base`.

## 9. Evidence

All under `E:\purge-build\gate-evidence\`:

| Folder | Content |
|---|---|
| `final-70d383b\` | Final gate: `m2-gate.md`, `m2-gate.json`, `crash-poweroff.log` |
| `final\` | Host logs of the earlier tries on the way to the final run (crash tries 1 to 6, fidelity, traps, install, reboot, elevated) |
| `engine-p902-commit_before-poweroff\` | The failed p902 case: crash row, journal, undo report with the `KeyExists` conflicts |
| `crash-try4-poweroff-rows\`, `crash-try5-poweroff-rows\` | Power-off rows of two tries |
| `g3-rerun\` | Gate re-run after the p902 fix: all pass |
| `settle-crash-coverage\` | Settle wait and the crash rows for the two fault points not hit |
| `ambient-rebuild\` | Null campaigns and the rebuilt ambient sets |
| `rig-crash-try1-hung`, `rig-crash-try2-poweroff-lost-marker`, `rig-crash-try3-winre`, `rig-fidelity-try1-check-and-npp-churn`, `rig-traps-try1-expiry-refused` | Rig bugs |
| `cleanpro\` | Clean-Pro runs, gate reports `cp-gate` and `cp2-gate`, ambient set |
| `m1a-rerun\` | M1a campaign `r4-` and its score in `truth-r4\` |

In the repository: `vm/truth/m2-ambient.json`, `vm/truth/m2-ambient-cleanpro.json`, `vm/truth/m2.sh`,
`docs/reviews/m2/`, `docs/DECISIONS.md`.
