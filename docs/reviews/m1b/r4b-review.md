# M1b review R4b: R4 fixes, rig host

Reviewed at `86aaf01` (head of local `m1b`). Reviewer changed no source code.

Scope: the R4 fix rounds (`fd5d542`, `4992a19`, `86aaf01`) against
`r4-review.md`, and M1B-RIG-HOST (`3b17232`), which R4 could not review.
Not reviewed: the 7-Zip smoke-run fixes in `crates/purge-scan` (parallel work).

## Verdict

**Not ready for the gate.** The R4 code fixes hold: B1, B2 and S8 are fixed,
and no way was found for the looser name key to match another product or a
generic word. The exec scorer (`m1b-exec.sh`) is now hard to pass wrongly.
The scan scorer (`m1b.sh`) is the problem: it fails two criteria on a correct
engine, and it can pass four on a wrong one.

- **Cannot pass:** K16 (B1: the scorer rejects the committed replay diff), K6
  (B2: true leftovers at Weak or Blocked are policy, and count as mismatches).
  Probably also K5 for `python312-with-313` (S5).
- **Can pass wrongly:** K9 (S1), K1 to K6 (S2, S4), every criterion (S3), K14 (S6).
- **Cannot run as designed:** G2 and G3 for powershell and temurin. Their truth
  is not frozen and their labels have never met a capture (S4).

**Ready for the gate: no.** It is ready after:

1. B1 is fixed (a few lines) and B2 has a written ruling.
2. S1, S2 and S3 are fixed in `m1b.sh`, with one bad-input control each in the
   selftest.
3. `m1b-freeze` has run, the labels are checked against the captures, and the
   launcher rules of S4 are added. One run of `python312-with-313` settles S5.
4. S6 is fixed or accepted in writing.
5. The smoke-run findings are closed, and the `svc-svchost` conflict is
   decided, not loosened (see "Seen in passing").
6. `cargo xtask ci` has passed once from an unelevated shell (R4 item 5, still open).

Evidence labels:

- **experiment**: a run against this commit on this host (Windows 11 26300,
  elevated shell, `CARGO_TARGET_DIR=E:\purge-build\review-r4b`, deleted afterwards).
- **reading**: confirmed by reading the code; no run.
- **suspected**: not confirmed.

## Reviewed

Read by the reviewer, no delegation: the three fix diffs, `vm/truth/m1b.sh`,
`m1b-exec.sh`, `m1b-traps.json`, `m1b-replay-diff.json`, `_m1b_sample`, the
label files and `mk_labels.py`, `vm/rig.ps1` (m1b modes), `run-app.ps1`
(hooks), `m1b-msi-tables.ps1`, `m1b-traps.ps1` (case table, phase runner),
`m1b-crash.ps1` (cut proof), `vm/rigtool/src/traps.rs`, `score.rs` and
`truth.rs` (the parts the gate reads), `vm/RIG.md` section 12.

Runs (all passed unless a finding says otherwise):

- `rig-m1b-exec.ps1 -Mode m1b-x-selftest`: 41 of 41, including the 25 bad-run
  mutations.
- `bash truth/m1b.sh --selftest`: 5 of 5.
- `m1b.sh --evaluate` on the sample with the committed replay diff: see B1.
- `cargo xtask replay-diff`: reproduces the committed file (3 rows, 0
  unexplained, 0 promotions, 1 new Safe).
- `cargo xtask replay --run vm/runs/7zip --app 7zip`: 1 item, see the B1 row below.
- `cargo test`: `purge-identity --lib` (67), `purge-scan --test sys_task` (29),
  `purge-harvest --test m1b sys_task` (4), `purge-exec --lib
  gone_msi_products_follow` (1), `purge-engine --test engine e2e_7zip` (2),
  `xtask replay_diff` (1).
- No ignored test, no rig test, no VM, nothing that changes system objects.

## The R4 fix rounds

| Id | Status | Note |
|---|---|---|
| B1 | fixed (experiment) | The replay offers `HKU\<sid>\Software\7-Zip`, Safe and preselected. The evidence is `AppNamedKeyWithRootRef` (Tier A, the root recorded at harvest) plus `ExactFullName`; the name alone still gives Likely. Attack below. |
| B2 | fixed (experiment, reading) | Harvest records a COM-only task only when every handler's CLSID is in `fp.anchors.clsids`. SYS-TASK reads the class keys only for a task that is otherwise Safe, and treats anything but `NotFound` as registered. Limits in M10. |
| S1 | fixed (reading, selftest) | The journal is read after the boot and before recovery. The record tag `rec` and the line framing match the real journal (`journal/frame.rs`). |
| S2 | partly | `unexplained == 0` is required for both execdiffs and for exec/resume crash rows. Undo-traps still has no execdiff. |
| S3, S5, S7 | fixed (selftest) | Each has a mutation that fails the named criterion. |
| S4 | fixed (reading, selftest) | Minimums are constants. The cases hash is compared per run. |
| S6 | partly | One engine hash and one commit over all runs. The clean check covers `crates bins tools Cargo.toml Cargo.lock` only: `kb/` is compiled into the engine (`deny.json`, `shared-iids.json`, `hosts.json`) and is not checked. The commit is HEAD at run time, not at build time. The scan runs record no build at all (S2). |
| S8 | fixed (experiment) | Per-SID lists are journalled and applied in validate, record, `set_gone` and `bind_user`. An old journal keeps SID-filed registrations closed. |
| S9 | fixed, and it broke K16 | The diff covers 7-Zip and a promotion is unexplained unless named. The new reason name is what B1 below trips on. |
| R4 "add the bundled 7-Zip copy as a trap" | not done | No unit case for `…\Inbound Download Manager\app\tools\7-Zip`. G2 and G3 cover it: the folder is in snap 0, so an offer scores danger. |
| R4 item 5, R3a M1 to M4 and M6 | not done | No unelevated `xtask ci` run. No line in `docs/DECISIONS.md` for the R3a minors. R4 M1 (data root for G7) is undecided, see S6. |

Nothing was made worse in the engine. The S9 fix and the rig-host package
were written side by side and disagree (B1).

Attack on `full_name_key` (`crates/purge-identity/src/tokenizer.rs:310`):

- A group is dropped only when it holds a version or architecture tag and
  otherwise only `edition`, `bit` or `version`. Only names with such a group
  change key. A segment or a name whose key is empty never matches
  (`matcher.rs:268`).
- Generic word: `Tools (x64 edition)` has name matching disabled. `Edition`,
  `x64`, `(x64 edition)`, `Zip` and `7` do not match 7-Zip (experiment, the
  commit's tests).
- Two products made equal: `Foo` and `Foo (x64 edition)` now share a key;
  before, the second was `foo edition`. `Foo (2023 edition)` and
  `Foo (2024 edition)` were already equal. The pair is the same product in two
  builds in every case found.
- The other callers (`reg_software.rs:323`, `fs_appdata.rs:494`,
  `coproducts.rs:156`) compare other apps' keys. Those keys only lose the
  qualifier, so the "another installed app carries this name" tests match
  more, not less.
- Residual, not new: with `7-Zip 24.08` and `7-Zip 24.08 (x64 edition)` both
  installed, REG-SOFTWARE protects the shared `Software\7-Zip` key only by its
  foreign-reference test; a non-vendor product key has no sibling-name test.
  The `(x64)` name had the same gap before.

## Blocking

### B1. K16 fails on the committed replay diff (experiment)

`vm/truth/m1b.sh:303-305`, `tools/xtask/src/replay_diff.rs` (`REASONS`).

- The scorer requires the diff's `reasons` list to be a subset of the four
  design names. Since `4992a19` the file (schema `purge.replay-diff/2`) lists
  five: `promotion_justified` was added.
- Run: the sample evidence with the committed `m1b-replay-diff.json` gives
  `K16 G1 replay diff: unexplained=0 rows_without_allowed_reason=0 (limit 0) FAIL`.
- The sample passes only because its `replay-diff.json` is hand-made.
- Fix: judge rows, not the declared list. Require `unexplained == 0`, every
  row's reason in the four names, `promotions == 0` (or each justified row
  named in `M1B_GATE.md`), and the five apps present under `apps`. Record the
  fifth reason in the design or in `docs/DECISIONS.md`.

### B2. K6 counts policy as a mismatch (experiment on M1a data, reading)

`vm/truth/m1b.sh:149-156`, `docs/M1B_DESIGN.json` K6.

- Every true leftover listed outside Safe or Likely is a mismatch.
- The M1a score, which passed its gate, has such items: firefox 4 hits at Weak
  and 1 at Blocked, firefox-tb the same, vscode-user 1 at Blocked
  (`vm/truth/m1a-score.json`). FS-TEMP leftovers are Weak by design
  (`vm/truth/FROZEN.md:109-115`), and vcredist's truth is mostly those.
- The smoke run adds one: the WER report at Blocked.
- The script follows the design text, so the text needs the ruling. Proposal:
  a leftover below Likely is a mismatch only when its scanner is an M1b
  scanner; Weak under an M1a scanner is as before. Write the ruling to
  `docs/DECISIONS.md` and change K6 in the design and the script together. Do
  not let the gate run decide it.

## Serious

### S1. K9: nothing proves a trap was planted (reading)

`vm/truth/m1b.sh:236-245, 385-391`, `vm/rigtool/src/traps.rs:488`,
`vm/guest/riglib.ps1:58`.

- `rigtool traps` reads the plan and the trap file only. 32 of the 44
  expectations are `absent`, `protected` or `not_preselected`: an object that
  was never planted meets them.
- A failed plant phase does not stop the run: `Phase` records the error and
  goes on. The scan still writes a plan, and `m1b.sh` never reads the phases
  or `m1b-traps-planted.json`.
- Every post-phase case is of the guard kind except `msi-remnants`. A post
  phase that fails after its first case passes 6 of 7 cases unseen.
- Trap targets are constants in the JSON and computed in the guest. Two depend
  on the Node version (`0DD75A3F…`, `{F3A57DD0-…}v20.18.0`) and two on the WER
  hash. No test compares them with what the guest plants.
- A case that found its object already there is `skipped` in the planted
  record and scores as a pass.
- Fix: in collect, require `m1b-traps-planted.json` with all 26 cases `ok` and
  not skipped, and every expectation target among the planted targets (or
  marked "not planted by design" in the trap file). Fail K9 otherwise.

### S2. The scan runs are not checked or bound (reading)

`vm/truth/m1b.sh` (collect), `vm/rig.ps1` (m1b modes).

- No check of `finished` or of the phases of any run. `m2.sh` and
  `m1b-exec.sh` have one. A run whose launch or uninstall phase failed is scored.
- No engine hash, commit or clean-source record in an m1b scan run, and no
  comparison across runs. This is R4 S6 again for the scan side: clean, dirty,
  trap and CleanPro runs can come from different builds, or from an older
  campaign left in `runs/`.
- The trap file and the label files are not hashed into the score.
- An empty plan passes K1 to K6: danger 0, precision null, no protected item,
  no hit. For node, vcredist, powershell and temurin no other criterion
  applies, so a scan that offers nothing passes all four apps.
- Fix: per run require `finished`, every phase ok and a plan with at least one
  item where truth has a leftover; record engine sha256, commit and source
  state in `run.json` and add a BIND row as in `m1b-exec.sh`; write the
  sha256 of the trap file and of each label file into `m1b-score.json`.

### S3. A custom configuration still prints PASS and exits 0 (experiment, reading)

`vm/truth/m1b.sh:55-63, 314`.

- `M1B_APPS=7zip` gives `pass: true` and exit 0; only `gate_config: custom`
  tells. The selftest relies on this.
- `M1B_LABELS` (other truth), `M1B_CLEAN`, `M1B_DIRTY`, `M1B_CP`, `M1B_RUNS`,
  `M1B_BUDGETS`, `M1B_REPLAY_DIFF` and `M1B_REPLAY_SCORE` are not even marked
  custom.
- Fix: a non-default value of any of these gives `gate: false` in the score
  and a last line "not a gate score". Only the default configuration may print
  the gate verdict. Let the selftest read `pass`, not the gate field.

### S4. Labels: a still-installed launcher's MSI registration is "leftover" (reading, suspected)

`vm/truth/labels/python313.json`, `python313-with-312.json`,
`vm/rigtool/src/truth.rs:311-350`, `vm/truth/labels/powershell.json`.

- `python313-with-312`: the 3.13 install upgrades the launcher inside the
  window, and the launcher stays. `python.json` names the 3.12.7 launcher's
  product code in seven rules; `python313.json` has none, because the code is
  not known yet.
- The ARP anchor covers the launcher's `Installer\Products`, `Features`,
  `UserData\S-1-5-18\Products` and `Uninstall` keys. It does not cover the
  `Components\<c>` client values, the `UpgradeCodes` value, the
  `Installer\Dependencies` key, `C:\Windows\Installer\*.msi`, the `SourceHash`
  file or the `Package Cache\{code}v…` directory. These default to leftover.
- Those are the targets of REG-ARP-MSI, SYS-BURNDEPS and FS-PKGCACHE. If the
  engine offered one as Safe, K1 and K4 would count a hit, not danger.
- `python312-with-313` is safe from this: the launcher is in snap 0, and an
  offer of a snap 0 object scores danger (`score.rs:861`).
- PowerShell (suspected, from the MSI's defaults `USE_MU=1`, `ENABLE_MU=1`):
  the install opts the machine into Microsoft Update
  (`…\WindowsUpdate\Services\7971F918-…`). That is Windows state, and no label
  or deny rule names it; it would be leftover. Check the freeze diff.
- The jump-list hashes do no harm if wrong: an unmatched jump list falls to
  the default label, which is also leftover. The `PYTHON|PYTHONW` Prefetch rule
  also matches the kept version's trace (M12).
- The `Documents\PowerShell` and PSReadLine user_data rules, the launcher
  kept_owner rules and the PythonCore first-leftover rule read correctly.
- Fix: run `m1b-freeze`, add a python313 raw run, read the launcher's product
  code from it and add the seven `python.json`-style rules; or extend
  `KeptAnchors` to the product-code-named objects listed above, which also
  covers the next unknown product.

### S5. K5: `python312-with-313` probably cannot reach 29 items (suspected)

`vm/guest/apps.ps1:247`, `vm/truth/m1b.sh:143-148`.

- 3.13 is a pre-app, installed before snap 0, with its launcher. The 3.12
  install leaves the newer launcher alone. The launcher is then not in the
  diff, so truth has no kept_owner item for it and `protected_n` stays under 29.
- This fails closed, and safety does not depend on it (S4, the snap 0 rule).
  But the gate cannot pass as scripted.
- `python313-with-312` should reach the count only if the launcher upgrade
  rewrites its keys; values that did not change are not in the diff either.
- Fix: one run of each pair before the campaign. If the count is short, count
  the kept_owner rule matches over snap 2 (objects, not diff items) in
  rigtool, and keep "none listed below Protected".

### S6. K14 trusts the budget run (reading)

`vm/truth/m1b.sh:268-296`, `vm/rig.ps1` (`Invoke-M1bBudgets`).

- The exit code of each engine run is in `budgets.json` and is not read. A
  harvest that fails late still has a time and phase lines.
- The number of rounds is not checked: one warm run is a median.
- Nothing shows that the cold round was cold. With `-KeepCache`, or when the
  cache folder is left in place, `cold_cache` is null and the cold limits are
  met by a warm run.
- Without the data root (R4 M1) there is no cache, every round is cold, and
  the warm limits (0.3 s tables, 2.5 s added) fail. That choice is still open.
- The host and the program are recorded, not checked.
- Fix: require exit 0 for all 12 runs, 3 rounds per engine and step, and
  `cold_cache` set or a note that no cache existed; decide R4 M1.

## M1B-RIG-HOST, by part

| Part | Result |
|---|---|
| `rig.ps1` m1b modes | Sound (reading). Only the two rig VMs, base checked, the rig-exec engine refused, run names checked. `m1b-app` makes no null runs unless `-Nulls` is given, so the G8 set has no ambient set and fails closed (M7). `m1b-budgets` moves the host's table cache aside and leaves it. |
| `run-app.ps1` hooks | Order is right: pre plants before lists 1 and the harvest, between before the uninstall, post before lists 2 and the scan. A failed plant does not stop the run (S1). |
| `m1b-msi-tables.ps1` | Read-only, `OpenDatabase` mode 0, limits as `msi_db`. A one-row table keeps its shape (experiment on the PowerShell idiom). Used for replays only, not by the gate. |
| `m1b.sh` collect and evaluate | B1, B2, S1, S2, S3, S6. Missing input fails closed in every case tried. The timing regexes match the engine's real output (`cli.rs:241`, `framework/m1b.rs:115`). The score field names match rigtool's. |
| `m1b.sh freeze` | Sound. Two runs must agree on every non-ambient item. Not run yet: `FROZEN.md` says PENDING. |
| `m1b.sh --selftest` | Tests missing input and one removed file. It has no bad-run control: no wrong value is ever fed to the evaluator (as R4 S7 for the exec scorer). |
| `_m1b_sample` | Synthetic, and says so. It hides B1. Its `userdata` field is a boolean where rigtool writes a string or nothing. Replace it with a cut of the first real run. |
| `m1b-traps.json` | Each named verdict follows the design; table below. |
| Labels | S4, S5. |

Trap expectations against the design:

| Cases | Verdict in the file | Follows the design |
|---|---|---|
| svc-owned, task-owned, fw-owned, com-owned, msi-remnants | safe | yes |
| svc-owned-running | listed | yes |
| svc-shared, svc-svchost, task-similar-name, fw-same-display-name, fw-no-app, msi-remnants-foreign, pkgcache-foreign, instfolders, the TrapB twins | absent | yes; a listed parent is an escape (`traps.rs`: covers and inside both count) |
| svc-dependent, shareddlls-count, msi-shared-component, com-isimpledom, burn-shared-package | protected with the named blocker | yes |
| com-shared-class | protected, no blocker | weak: M1B-S-COM rule (c) names `ReferencedByOtherApp` (M3) |
| task-interpreter, tracing | not_preselected | yes |
| shellex-approved, eventlog (own), privacy (own), wer (own) | listed | the author's choice; right, each is "Likely at most" or "Safe only when dangling" in its scanner's rules |

## Seen in passing (not reviewed)

- **`svc-svchost` escape.** Cause: `crates/purge-index/src/sysobj.rs:669-676`.
  A System32 `svchost.exe` service takes its `ServiceDll` as its program, so a
  DLL in the app's folder makes the service the app's. R2a accepted that rule
  (`r2a-review.md:303`). The design's host list names `svchost.exe` as a host
  that is never the app's program, and the trap follows that. The two
  disagree. Decide which holds and write it down; do not change the trap to
  `listed` without that.
- **Evidence trust.** The 7-Zip key's Tier A evidence is read from the user's
  own hive and is marked `AdminOnly`. M1a behaviour, not looked into.

## Minor

- **M1 (reading).** K7's plan check accepts any band but Blocked, so Weak
  counts as listed. G1's K4 row loop does not require the five replay apps. No
  command writes `m1b-replay-score.json`.
- **M2 (reading).** K8 finds a suggestion by the substring `suggest_uninstall`
  and does not check that it names the Launcher.
- **M3 (reading).** `com-shared-class`: name the blocker `ReferencedByOtherApp`.
- **M4 (reading).** No expectation on the count-2 file
  `C:\Program Files\7-Zip\PurgeTrapShared2.dll` itself: the value is protected,
  the file may go with the folder. `msi-remnants` expects only the Products
  key, not TrapA's UpgradeCodes and Components values. TrapA's own Folders
  value has no expectation.
- **M5 (reading).** The selftest's design check reads only the first
  expectation of 15 cases.
- **M6 (reading).** `m1b.sh` K4 passes when no app has a Safe item. Require a
  non-null precision for 7zip on rig-base at least.
- **M7 (reading).** G8 through `m1b-app` needs `-Nulls 3`, or `m1b-apps -Ids`;
  say so in RIG.md 12.1.
- **M8 (reading).** `m1b.sh` takes the total time from the last progress
  stamp; time after it is not counted.
- **M9 (reading).** S2 leftover: `m1b-x-undo-traps` has no execdiff.
- **M10 (reading).** SYS-TASK class proof: a class in the hive of a user who
  is not logged on, or a packaged COM class, is not seen (the first is
  recorded). The executor has no program check for a COM-only task (recorded).
- **M11 (reading).** S6 leftover: add `kb` and `rust-toolchain.toml` to the
  clean check.
- **M12 (reading).** The `PYTHON|PYTHONW` Prefetch rule in the pair labels
  also matches a trace of the version that stays.
