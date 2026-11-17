# M1b review R4: integration, R3 fixes, exec rig

Reviewed at `758d55f` (head of local `m1b`). Reviewer changed no source code.

Scope: M1B-SCAN-INTEG (`afb1985`), the R3 fix rounds (`10a57b4` against
`r3a-review.md`, `5e2cf69` against `r3b-review.md`), M1B-RIG-EXEC (`758d55f`).

## Verdict

**Not ready for the gate.** No finding lets the scan offer another product's
object as Safe, and no way was found for a standard user to plant or poison the
MSI table cache. The gate itself is the problem: as the tree stands it cannot
pass two criteria, cannot run four steps, and can pass four criteria on a real
defect.

- **Cannot pass:** K7 (B1: the 7-Zip replay offers nothing) and K11 (B2: the
  fourth task variant can never be recorded).
- **Cannot run:** G2, G3, G4, G8. M1B-RIG-HOST is not in the tree: no
  `vm/truth/m1b.sh`, no `vm/truth/m1b-traps.json`, no `m1b-*` mode in
  `vm/rig.ps1`, no PowerShell or Temurin labels. R4 attack items 4 (trap
  expectations) and 5 (truth labels) could therefore not be done; they need
  their own read when that package lands.
- **Can pass wrongly:** K13 (S1), K10 (S2), K12 (S3, S5), every minimum (S4).

**Ready for the gate: no.** It is ready after:

1. B1 and B2 are fixed.
2. S1 to S5 are fixed in the rig; S6 and S7 are fixed or accepted in writing.
3. S8 is fixed or recorded in `docs/DECISIONS.md`; S9 is fixed (one line).
4. M1B-RIG-HOST is merged and its traps and labels are reviewed.
5. `cargo xtask ci` has passed once from an unelevated shell (R3b S1, still
   open in `docs/DECISIONS.md:104`).

Evidence labels:

- **experiment**: a run against this commit on this host (Windows 11 26300,
  elevated shell, `CARGO_TARGET_DIR=E:\purge-build\review-r4`).
- **reading**: confirmed by reading the code; no run.
- **suspected**: not confirmed.

## Reviewed

1. By the reviewer: `bins/purge-engine/src/pipeline.rs` (table cache,
   exemption lists, warnings), `crates/purge-index/src/ownership/cache.rs`,
   `crates/purge-win/src/sid.rs` (admin-only check), `tools/xtask/src`
   (`replay_diff.rs`, `no_new_walks.rs`, `check_deps.rs`,
   `scanner_coverage.rs`), `bins/purge-engine/tests/engine/m1b_scan.rs`,
   `vm/truth/m1b-replay-diff.json`, `m1a6-replay.json`, `m1b-exec.sh`,
   `m1b-exec-cases.json`.
2. By three delegated readers, one each: the R3a fix round, the R3b fix round,
   the exec rig. Their B and S findings were re-read at the cited lines by the
   reviewer; their minor findings are marked "sub-reader" where not re-read.

Runs (all passed unless a finding says otherwise):

- `xtask check-deps`, `no-new-walks`, `scanner-coverage` (33 scanners, 97
  roots, 28 containers).
- `xtask replay-diff -o <scratch>`: reproduces the committed file, 1 row, 0
  unexplained.
- `xtask replay --run vm/runs/7zip --app 7zip`: see B1.
- `cargo test -p purge-engine --lib pipeline` (11), `--test engine m1b_scan`
  (11, 1 ignored), `-p xtask` (29, 1 ignored), `-p purge-scan --lib catalog` (4).
- No ignored test, no rig test, no purge-win or purge-exec test was run.

## R4 attack list

| Item | Answer |
|---|---|
| Replay diff row by row | One row: firefox `FirewallRule {AC21D679-…}`, new, Likely, not preselected, SYS-FIREWALL, `new_scanner`. Intended: the frozen truth labels that rule `leftover` (`vm/truth/m1a-frozen-firefox.md:59`). m1a.6 listed the same rule as a Blocked registry value under REF-ANY; that item is unchanged, so the rule now appears twice in the plan (M8). The diff does not cover 7-Zip (S9). |
| One reference walk per scan | Yes (experiment): `pipeline_one_reference_walk_and_one_ownership_build` passes and its probe would see a second walk. Scan time on the 591-program host was **not measured**: no release engine was built. G7 will fail its warm figures unless the data root is installed first (M1). |
| Exemption lists closed when the state is unknown | Yes (reading and experiment). `product_known_in` (`crates/purge-scan/src/framework/m1b.rs:575`) returns `None` on a source error, an empty answer, a bad code, or a per-user product of another or unknown user; `from_facts` opens only on `Some(false)`. The executor's act-time gate is weaker than the plan's (S8). |
| Trap expectations | Not reviewable: `vm/truth/m1b-traps.json` does not exist. |
| Truth labels, PowerShell and Temurin | Not reviewable: the labels do not exist. |

MSI table cache (asked for in the brief), reading plus `icacls` on this host:

- `DiskTableCache::open` accepts the directory only when it and every ancestor
  are owned by SYSTEM, Administrators or TrustedInstaller and no other
  principal has a write, delete, DACL or owner right
  (`crates/purge-win/src/sid.rs:398-441`); a reparse point anywhere refuses.
- `C:\ProgramData` grants Users `(CI)(WD,AD,WEA,WA)`. A `Purge` folder made by
  a standard user is owned by that user: refused. One made by a plain elevated
  `mkdir` inherits the Users write ACE: refused as a leaf. Only the protected
  DACL of `install/install.ps1` passes.
- `table_cache` creates `fp\msitables` only when elevated and only under a
  data root that already passes (`pipeline.rs:157-163`). A file is a miss
  unless its schema and key match; limits are re-applied on read.
- Result: a standard user cannot plant or poison the cache. The cost is M1.

## Blocking

### B1. K7 fails: the 7-Zip replay offers nothing (experiment)

`bins/purge-engine/tests/engine/m1b_scan.rs:312` (ignored test),
`vm/runs/7zip/run.json` (`"name": "7-Zip 24.08 (x64 edition)"`).

- `xtask replay --run vm/runs/7zip --app 7zip` at this commit: harvest finds 1
  root (good, the MSI component root), the plan has **0 items**.
- Snap 2 holds `HKU\<sid>\Software\7-Zip` with `FM` and `FM\Columns`, and no
  `Path` value, so REF-ANY has nothing either.
- The passing e2e test uses the name "7-Zip 24.08 (x64)". The real name is the
  one in the ignored test. The ignored test is the gate case.
- K7 needs the key listed at G1 and G2. G1 fails today; G2 fails the same way
  unless the live MSI `Registry` row is turned into a candidate, which the
  ignored test says it is not.
- Fix: the identity matcher, or offer the recorded per-user `Registry` row key
  (`fp.msi[].registry_rows`, `HKU\*\Software\7-Zip`) when the product is gone.
  Un-ignore the test and use the real name in both.
- Take care: the same VM has `…\Inbound Download Manager\app\tools\7-Zip`
  (another app's bundled copy). A looser name match must not reach it; add it
  as a trap.

### B2. K11 cannot pass: the COM-handler task is never recorded (reading)

`vm/truth/m1b-exec-cases.json:18-19`, `crates/purge-harvest/src/sysobj.rs:177-180`.

- `task-com` has one action, a COM handler. Harvest skips every task whose
  programs resolve to no file, even when the handler's CLSID is the app's.
- The smoke run in the commit message shows it: 3 of 4 tasks recorded.
- The scorer is right to fail it (every `full` row must pass, minimum 4), so
  the gate fails correctly, but it can never pass.
- Fix: record a COM-only task whose class is the app's own (and decide the
  R3b S2 "rests on attribution alone" note with it), or make the variant an
  exec action plus a COM handler. Do not lower `min_full`.

## Serious

### S1. K13: nothing proves a power-off landed inside the run (reading)

`vm/guest/m1b-crash.ps1:363-376, 422`.

- `hit` and `crashed` are set to true unconditionally for a power-off row.
- "Paused" means the journal length was stable for 6 s. For undo rounds the
  session is the finished exec's, so its length is stable from the first second.
- After boot only the boot id, exit codes and final state are checked.
- Wrong pass: the engine finishes before the cut; recover, resume, undo and
  fidelity are then trivially fine, 15 of 15.
- Fix: before `recover`, read the session journal; require no commit (exec) or
  undo-finish (undo) record and an open intent at the paused point; store that
  in the row and require it in `row_pass` (`vm/truth/m1b-exec.sh:262`).

### S2. K10: an added object never fails (reading)

`vm/rigtool/src/execdiff.rs:31`, `vm/truth/m1b-exec.sh:106`.

- An added record that no op authorises is `unexplained`, "never failing".
  The scorer requires only `ok`, `collateral == 0`, `guard_escapes == 0`.
- Wrong pass: the executor or undo leaves an extra value, rule, task or
  service (the spike found exactly this class: five extra values and keys).
- Fix: require `unexplained == 0` after the ambient set, in the scorer.
- Also: undo-traps has no execdiff, and crash rounds diff scoped snaps only.

### S3. K12: svc-running does not check the service still runs (reading)

`vm/guest/m1b-exec.ps1:285-307`.

- Service state is the registry tree. An executor that stops the service and
  then reports `Skipped/InUse` passes.
- Fix: record SCM state and PID before and after exec; require them equal.

### S4. Every minimum comes from the editable cases file (reading)

`vm/truth/m1b-exec.sh:171, 241, 250, 294`.

- `min_full`, the trap lists, `rounds_per_kind` and each point's `kinds` are
  read from `m1b-exec-cases.json`. Lowering a minimum, dropping a trap or
  moving a point to `not_reachable` gives PASS.
- Today's file is honest: all 19 `FAULT_POINTS` are listed and the
  unreachable reasons hold. One gap: `index.write` is listed for undo only but
  is also hit in exec (`crates/purge-exec/src/execute.rs:31`).
- Fix: hard-code 2/4/3, 6, 4 and 5 per kind in the scorer, as `vm/truth/m2.sh`
  does, and compare the cases hash with each run's saved copy.

### S5. K12: the same-name twin counts as "skipped" with no check of the planned rule (reading)

`vm/truth/m1b-exec.sh:186-192`.

- For `fw-same-name` the row passes when the twin is byte-equal and the op is
  not `Failed`. An absent op passes too (`ex` empty). The row is then counted
  in `act_skipped`, so "6 of 6 skipped" is really 5 skipped plus this.
- Wrong pass: the scan never offers the base rule (so nothing was at risk), or
  the executor skips it for the wrong reason.
- Fix: require the base rule `Done` and gone, the twin present and equal, and
  report the count as 5 skipped + 1 twin untouched.

### S6. Runs are not bound to one engine or to each other (reading)

`vm/truth/m1b-exec.sh:69-70`. Fidelity from one build can be scored with a
crash matrix from another, or with a stale `runs/<mode>`. Fix: engine sha256
and commit in each `run.json`; the scorer requires them equal.

### S7. The selftest never feeds the scorer a bad run (reading)

`vm/rig-m1b-exec.ps1:111-128`. The scorer is tested on an empty directory
only. Fix: one synthetic passing set and one-field mutations (collateral 1, a
deleted trap object, an overwritten impostor, an unreached point, 14 rounds).

### S8. R3a B1 is half fixed: the act-time gate opens every SID (reading)

`crates/purge-exec/src/plan_in.rs:127`, `crates/purge-exec/src/gate.rs:365`.

- The plan side is fixed: `gone_msi_products_for` gives a
  `UserData\<sid>\…` target only the products of that SID.
- The executor journals and applies the flat list. Its guard lets
  `UserData\<other user's sid>\Products\<P>` through. The comment at
  `crates/purge-plan/src/decide.rs:215-217` says the executor passes the same
  list; it does not.
- Scenario: a plan that names the second user's registration of the same
  ProductCode (a hand-made plan, or a later scanner defect). Only the plan-time
  check stands in the way, and the executor is meant not to trust the plan.
- Fix: journal the per-SID lists and apply them per op; or record the limit.

### S9. The replay diff leaves out 7-Zip and its reasons allow a promotion (reading, experiment)

`tools/xtask/src/replay.rs:51`, `tools/xtask/src/replay_diff.rs:232-262`.

- `M0_RUNS` is vscode, git, firefox, npp. G1 says "every M1a frozen snap";
  `vm/runs/7zip` and `vm/truth/m1a-frozen-7zip.json` exist. K16 is therefore
  silent about the one app M1b set out to change.
- `new_scanner`, `msi_blocker_added` and `policy_m1b` explain a row whatever
  the direction: Blocked to Safe and preselected under an M1b scanner is
  "explained". `differs` ignores blocker changes.
- Fix: add `7zip` to the diff; for the blocker reasons require that the band
  did not rise; print promotions to Safe as their own count.

## The R3 fix rounds

R3a (`10a57b4`), state at head:

| Id | Status | Note |
|---|---|---|
| B1 | partly | Scan and plan fixed, tests real. Executor: S8. |
| S1 | fixed | `ScanCtx::program_gone`. No test for a missing volume. |
| S2 | fixed, neighbour open | `Own` means "one version is a candidate"; a sibling's second version leaves it `Own`, and its interface is chained and listed Likely (`com_class.rs:1556`, sub-reader). |
| S3 | fixed | Walk completeness caps COM and SHELLEX; pipeline warns. |
| S4 | fixed | `bundle_gone` still trusts the inventory alone; the plan's list covers it. |
| S5 | fixed | Tests cover App Paths and tasks only. |
| S6 | partly | Node closed. `.` and `..` are not relative (M5). |
| M1, M2, M3, M4, M6 | not fixed, not recorded | Need a line each in `docs/DECISIONS.md`. |
| M5, M7, M8, M9, M10 | fixed | M9 and M10 in `afb1985`. |

R3b (`5e2cf69`), state at head:

| Id | Status | Note |
|---|---|---|
| S1 | fixed in code | The unelevated `xtask ci` run is still to do. |
| S2 | fixed | No service test; no `execute`-level test with a port rule. |
| S3 | fixed as asked | Roots are checked at `Run::start` only, not on resume or undo. A fingerprint root's `trust` is ignored (suspected). |
| S4 | fixed per the ruling | Lifted shapes proven for one value form each. |
| M1, M8, M10 | deferred, recorded | `docs/DECISIONS.md:110`. |
| M3 | partly | `Run::settle_open` (`execute.rs:1562`) still writes `done` for a probed object with no flush. |
| M2, M4, M5, M6, M7, M9 | fixed | M2 and M6 have no test. |

Nothing was made worse. No path was found where a fix lets undo or recovery
create an object outside the recorded roots or delete without a backup.

## Minor

- **M1 (reading).** The disk cache is used only after `install.ps1` made the
  data root. On the 591-program host there is none, and G7 is "read-only", so
  every run reads every package: the K14 warm figures (0.3 s tables, 2.5 s
  scan) cannot be met there. Decide: install the data root on the host for
  G7, or measure warm in a VM.
- **M2 (reading).** `no-new-walks` is a text match on `.walker(` and
  `refscan::scan`. `RegistrySource::walker(reg, …)`, `use …::refscan::scan`
  and a hand-rolled `subkeys()` recursion pass. None exists today.
- **M3 (reading).** `check-deps` rule 5 strips from any column-0
  `#[cfg(test)]` to the next column-0 `}`; a `#[cfg(test)]` on a top-level
  `use` with braces would hide the code after it. The list has no task
  `Run`/`RunEx` and no `MsiProvideComponent`; none is used today.
- **M4 (reading).** `scanner_coverage::claimed` is satisfied by any root at
  or above the place; the `Services` root alone claims `FirewallRules`.
- **M5 (reading, from the S6 fix).** `has_relative_argument`
  (`crates/purge-index/src/sysobj.rs:450`) treats a token of digits and dots
  as a number, so `.` and `..` are not relative. A task `<root>\tool.exe .`
  with a foreign working directory counts as the app's.
- **M6 (reading).** The 9 M1b registry scanners have no positive control in
  `tests/reg/hostile.rs`; a scanner that offers nothing passes there. The
  `#[path]` includes of other crates' test worlds in `m1b_scan.rs` are fine,
  but a change to a world silently changes the engine test.
- **M7 (reading).** `vm/truth/m1b-exec.sh:278-281`: `any(row_pass)` lets a
  repeated round hide a failed one. Require every row of a key to pass.
- **M8 (experiment).** The firefox rule is in the plan twice: the Blocked
  registry value (REF-ANY) and the Likely `FirewallRule`. Drop the value
  when the typed object is offered.
- **M9 (sub-reader).** `exec --fp` refuses the whole run when one selected
  object has no `object_fp` (`cli/exec.rs:907`); say so in `--help`.
- **M10 (sub-reader).** `Stop-XVm` in `finally`
  (`vm/rig-m1b-exec.ps1:263, 369`) powers off and restores the rig VM even
  when this call never started it. Only the two rig VMs are touched.
- **M11 (sub-reader).** The design's Full "rule with service and profile"
  variant became `refused` in the cases; record the decision.
- **M12 (suspected).** `UpgradeCodes\<U>` value `<P>` is not filed under a
  SID and gets the flat gone list. `product_known_in` compares with
  `sys.user_sid()`, which becomes the interactive user under the M3 broker
  while MSI state is asked for the calling account.
