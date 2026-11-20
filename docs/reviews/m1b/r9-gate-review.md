# R9: closing review of the M1b gate report

- Date: 2026-11-21. Read-only review at HEAD 3f95da7 plus the uncommitted doc edits.
- Reviewed: `docs/M1B_GATE.md` (new), the two 2026-11-21 rows in `docs/DECISIONS.md` (:138, :139), the new top section
  of `docs/HANDOFF-m1b.md` (:3-11).
- Against: `docs/M1B_DESIGN.json` (`gate_procedure`, `gate_criteria`), `vm/truth/m1b-score.json`,
  `vm/truth/m1b-exec-score.json`, `E:\purge-build\gate-evidence\m1b-gate6\final\`, `...\m1b-gate7\`, `vm\runs\_old\`,
  the scorers, `git log 7e885aa..HEAD`, `E:\purge-build\ci-unelev-laptop*.log`.
- Nothing was rerun (no scorer, no VM, no build).

## Verdict

**The PASS verdict is justified. No blocker.** Six S findings are doc fixes in `M1B_GATE.md` (one wrong evidence
pointer, one design criterion with no row, four missing limits or deviations). The numbers in the report match the
evidence.

## What was checked and holds

- Both score JSONs in `vm/truth/` are byte-equal to the copies in the evidence folders.
- Scan: 153 rows, 153 pass, `failed` 0, `gate` true, one engine `23529600…`, one commit 7e885aa. Every number in the
  section 2 table matches a row (app lists, 29 / 42 / 44 / 2 protected items, 26 traps x 3, replay 3 rows /
  unexplained 0 / promotions 0, all K14 values, 20 budget runs, ATK product code).
- Executor: PASS, failing none, missing none. 5 runs, engine `52a8ee29…` staged = installed, commit 3f95da7, source
  clean, cases `672e6991…`, ambient `49214ff7…` declared = guest in the four VM runs, 6 null runs per mode. K10, K11,
  K12, K13, E1 values and the step times (235 / 233 / 139 / 5492 s) match the score and the step logs.
- `target\rig-exec\release\purge-engine.exe` on disk hashes to `52a8ee29…`; `C:\purge-build\gate\release\purge-engine.exe`
  hashes to `23529600…`.
- R8b S1 is closed: `vm/truth/m1b-exec.sh:111` requires the three `act_service` names, the same three as
  `vm/truth/m1b-exec-cases.json:104`, and the gate run passed 3.
- G1 is bound even though the BIND row's step reads "G2-G4, G7, G8": `m1b.sh:926-947` binds the replay block (the
  diff's sha256 and the replay-diff exit code).
- K1's `DenyListed` condition is checked by the scorer (`m1b.sh:1111`).

## B (blocks the verdict)

None.

## S (must fix in the docs)

**S1. The failed elevated run is in a different folder than the report says.** `docs/M1B_GATE.md:105`.
The rig names an `_old` folder after the time of the move, and it holds the run that was there before.

| Folder | Content |
|---|---|
| `vm\runs\_old\m1b-x-elevated-20261120-234410` | first campaign's run: 2026-11-19 12:42, commit 7e885aa, cases `9b2fa951…`, pass=True |
| `vm\runs\_old\m1b-x-elevated-20261120-234932` | **the failed gate run**: 2026-11-20 23:44:10, commit 3f95da7, scm exit 101, pass=False |
| `vm\runs\m1b-x-elevated` (= `m1b-gate7\runs\m1b-x-elevated`) | the retry: start 23:49:32, pass=True |

Fix the path to `...-234932`. The failed run's `job-tests.log` and `elevated-tests.json` are also not in
`m1b-gate7` (only the step log `g5-x-elevated.log` is); copy them there, since `vm\runs\_old` is not kept evidence.

**S2. G0 / K15 has no row and no evidence pointer.** K15 (`gate_criteria`, step G0: the release build links no
service, task or firewall write function and no executor path) is in neither scorer and is not named in the report.
The only trace is `M1B_GATE.md:87` ("unelevated `xtask ci` pass at 3f95da7"), with no log path.
The evidence exists: `E:\purge-build\ci-unelev-laptop.log` (2026-11-20 23:41, 13 minutes after the 3f95da7 commit,
`xtask ci: all steps passed`, `check-deps: ok` at :3841-3843, no-new-walks and scanner-coverage ok), and
`ci-unelev-laptop-7e885aa-pass.log` for the scan commit. Add a G0 row with K15 to section 1 or 2, name both logs,
copy the 3f95da7 log into `m1b-gate7`, and say that the log itself does not record the commit (file time only) and
that the run was unelevated.

**S3. Twenty-six of the 153 passing rows are empty, and the report does not say so.** `M1B_GATE.md:16`, `:29-32`.

- K4 (`precision_safe`) is `None` ("no Safe item: null, not counted as a pass") for 7 of 8 clean apps, 6 of 7 dirty
  apps, 2 of 3 Clean-Pro apps, and for npp in the replay: 16 rows. On the VM sets only 7-Zip has a Safe item.
  precision_safe 100 % is therefore shown by 7-Zip (three sets) and by the vscode, git, firefox and 7-Zip replays.
- K5 is "n/a (no kept_owner/protected truth item)" in 10 rows.

The design allows both, and the verdict stands, but "153 of 153 criteria pass" overstates what was measured. State
the counts and name the apps that carry K4.

**S4. The `danger_kept` items are not named.** K1 says a danger item listed Blocked "is danger_kept and is named in
the report". The score has `danger_kept=1` for clean python, python312-with-313, python313-with-312 and vcredist, and
for dirty vcredist: the `bam\State\UserSettings\<sid>` value, Blocked, `DenyListed`. `M1B_GATE.md:29-30` says only
"danger_offered 0". Add the items.

**S5. K14 was measured on a 205-entry host, and the stated reason covers the CPU only.** `M1B_GATE.md:36-42`,
`DECISIONS.md:135`. The design sets G7 "on the 591-program host". The laptop's harvest log reads "205 entries" and 107
MSI packages (`m1b-gate6\final\m1b-budgets\m1b-harvest-1.log`). "A faster CPU only lowers them" does not answer a host
with almost three times the programs, where the added phases have more to read. The report admits that ATK is a
lighter program; it should also give the 205 against 591, and say that K14 at the design's scale rests on the desktop
precheck (+1.80 s scan, +1.86 s harvest, components 1.22 s against 1.5 s), which is under every limit but is not a
gate-bound run. This is a limit to record, covered by the user ruling; it does not change the verdict.

**S6. The "byte-identical" release engine is an inference, not a measurement, and the wording hides one fact.**
`M1B_GATE.md:107-108`, `DECISIONS.md:139`, see "BIND caveat" below. No release engine was built at 3f95da7, so no hash
shows identity. Also 6fd053a changed `crates/purge-win/src/reg_write.rs`, and purge-win is linked by the release
engine; "the release engine has no purge-exec" is not the whole reason. Either build the release engine at 3f95da7
into the gate target folder and record that the hash is still `23529600…`, or reword to what is shown: no source the
release build compiles changed between 7e885aa and 3f95da7.

## M (minor)

- **M1. K12 is not the criterion as written.** The design says "6 of 6 changed objects skipped, 0 deleted". The
  result is 5 skipped plus one same-name firewall twin untouched, with the planned base rule deleted (`exec: Done`,
  `base_gone: true`). That is the R4 S5 fix and is correct; `M1B_GATE.md:63` reports it truthfully but does not say
  it departs from the K12 text, and `M1B_DESIGN.json` K12 / `M1B_DESIGN.md:54` still read "6 of 6". Add one sentence
  with the R4 S5 reference.
- **M2. Gate-to-criterion mapping differs from the score.** `M1B_GATE.md:52` lists E1 under G5 (as the design does);
  the score JSON puts E1 in gate G6. `:56` lists K10 under G6; the score puts K10 in G5 (it includes the 44 crash
  execdiffs). Harmless, both gates pass; note it or align the scorer later.
- **M3. The cause of the flake is stated as fact.** `M1B_GATE.md:103-104`, `DECISIONS.md:138` ("another process
  briefly held a handle", "a transient foreign handle"). The log shows only `Ok(Marked)` at `scm.rs:283` and `:466`,
  in two tests of one 0.51 s multi-threaded run. A sibling test thread in the same process
  (`query_existing_services_read_only` opens services) is at least as likely as another process. Write "a handle held
  elsewhere (not identified)".
- **M4. The retry decision is not marked (user).** `DECISIONS.md:138` is a coordinator decision on a gate criterion;
  the design has no retry rule. Get the user's ok or mark it as the coordinator's.
- **M5. E1 binds less than the other runs.** The elevated run records commit, clean source and the cases hash, but no
  hash of the test binaries (`build.sha256: null`). The BIND cell at `M1B_GATE.md:60` reads as if "one engine" covered
  all 5 runs; it covers 4.
- **M6. Evidence not yet committed.** `vm/truth/m1b-score.json`, `m1b-exec-score.json`, `m1b-replay-score.*`,
  `m1b-evidence/` are untracked and `m1b-replay-diff.json` (which K16 judges) is modified. Commit them with the report.
- **M7. Engine file time.** `C:\purge-build\gate\release\purge-engine.exe` is dated 02:31, before the 7e885aa commit
  (03:36). 7e885aa changes only `docs/MIGRATION-laptop.md`, so the binding holds; worth one clause.
- **M8. History not verified here.** Section 4 numbers (133/153, 148/153, engine `45fbbee0`, "25 service crash rows",
  the host replay of the failed execdiffs) were not checked against evidence in this review.

## The BIND caveat (question 3)

- **Shown:** the scan score binds one engine `23529600…` and commit 7e885aa; the executor score binds `52a8ee29…`
  and 3f95da7.
- **Shown at source level:** `git diff 7e885aa 3f95da7` touches, outside `vm/` and `docs/`, only
  `crates/purge-exec/**` and `crates/purge-win/src/reg_write.rs`. `reg_write` is behind `#[cfg(feature = "write")]`
  (`crates/purge-win/src/lib.rs:37-38`). `check-deps` in the 3f95da7 ci log says "a default build links [purge-exec]
  into nothing and purge-engine has no purge-win/write". No Cargo.toml or Cargo.lock change. So the release build
  compiles the same sources.
- **Only asserted:** byte identity. No release binary from 3f95da7 exists to hash (S6).
- **Is one milestone gate with two bound commits sound?** Yes, here. The two halves use different binaries by design
  (release against rig-exec), each half is bound inside itself, and the only engine changes after the scan gate are
  in code the release build does not compile. The scan code inside the rig-exec engine is also unchanged since
  7e885aa. What is lost is one thing: the scan evidence was not scored with the rigtool of 3f95da7
  (`execdiff.rs`, `ambient.rs`, `items.rs`, `main.rs` changed). That is acceptable because the scan verdict is the
  one scored at 7e885aa and the report says so. The reverse condition in `DECISIONS.md:139` ("an engine change
  touches the release build before M3") is the right one.

## The elevated flake (question 4)

- **Is the retry the run the scorer bound?** Yes. `m1b-gate7\runs\m1b-x-elevated\elevated-tests.json` is byte-equal
  to `vm\runs\m1b-x-elevated`, start 23:49:32, commit 3f95da7, cases `672e6991…`, all six targets exit 0, act_service
  3 tests. The retry reused the same test binaries (the build step took one second).
- **Is taking the retry acceptable?** Yes, with the fixes above.
  - Both failures are the tests' own clean-up assertion `delete(..) == Ok(Deleted)`; every assertion on the service
    before it passed.
  - `Marked` is a designed result (`crates/purge-win/src/scm.rs:1271-1288`), and the executor maps it to a pending
    delete; the tests are stricter than the engine contract.
  - Same commit and binaries passed before (first campaign) and after: 2 of 3 runs.
  - The limit: this is one retry with no rule behind it and an unidentified handle holder (M3, M4). The follow-up at
    `M1B_GATE.md:116` should be done before the next gate that counts E1.

## Summary

| Class | Count |
|---|---|
| B | 0 |
| S | 6 |
| M | 8 |
