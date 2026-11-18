# M1b review R5: the gate fix round (engine Burn link, shared indexes, rulings 2026-11-18, R4d S1-S4)

Reviewed at `a954d90` (`git diff ee43fa2..a954d90`: `ba48ae7`, `b89ffde`, `a954d90`), against the failed
gate evidence in `E:\purge-build\gate-evidence\m1b-gate3` and the run directories in `vm/runs`. Reviewer
changed no file in the repository, built nothing and ran no VM.

## Verdict

**The engine change is safe. The next full campaign will still fail: three blocking findings, all on the
scoring side, none of them a safety problem.**

- Engine (focus 1): no way was found for the Burn link or the shared indexes to produce anything but a
  `ReportOnly` item from the new rule, or to move another scanner towards deleting more. The suggestion
  fails closed for a forged per-user bundle, an unloaded hive, unknown profiles, an incomplete Burn index
  and a Launcher of another version. One test gap (S4).
- Scorer (focus 2): the rulings are implemented as ruled and K1, K8, RUN, BIND, SANITY and K14 fail on
  missing input. Two gaps: a trap run without a pre record passes RUN (S2), and K1 accepts any Blocked
  danger item whatever its blocker (S3). The ambient folder rules swallow nothing but the ruled noise on
  the archived runs and no frozen truth item (experiment).
- Campaign (focus 3): three lines will fail again for reasons that are not the engine's:
  - **B1**: the Launcher suggestion that K8 asks for is scored as a danger item offered and as a protected
    item listed below Protected. K1, K5 and K6 fail for `python` on rig-base and on Purge-CleanPro.
  - **B2**: K8 asks for the suggestion on dirty-base too, where Python 3.11.9 and 3.13.1 are installed. A
    correct engine gives none there.
  - **B3**: K14's new warm-cache line needs the cold scan round to read MSI tables. The cold harvest that
    runs just before it fills the disk cache, so the cold scan reads none.
- Also: the `rigtool.exe` in the tree predates the ambient folder rules and nothing rebuilds or checks it
  (S1).

Evidence labels: **experiment** (a read-only command on this host, outputs in the scratchpad),
**reading**, **suspected**.

## Reviewed

Read: the full diff; `crates/purge-scan/src/sys_burndeps.rs` whole; `crates/purge-harvest/src/burn.rs`
(`harvest`, `linked_components`); `harvest.rs` (`SharedIndexes`, `harvest_report_with`); `coproducts.rs`
(`harvest_candidate`, `candidates`); `pipeline.rs` (`uninstall`, `table_cache`, `CountingCache`);
`purge-scan` `framework.rs` (`run`, `seal`, the candidate builder) and `framework/m1b.rs`
(`msi_blockers`); `purge-plan` `decide.rs` (`guard_and_policy`); `purge-policy` `band.rs` rules;
`purge-guard` `deny/shared.rs`; `vm/rigtool/src/ambient.rs` and `score.rs` (`eval_item`, `score_plan`,
`protected_listings`); `vm/truth/m1b.sh` diff and the K14, K8, RUN sections; `vm/rig.ps1`
(`Invoke-M1bBudgets`, `Get-PurgeDataRootVerdict`, `Get-M1bGateApps`, `Get-M1bRigInputs`);
`install/install.ps1` (`Get-PurgeDataLayout`, `Get-TreeVerdict`, `Test-Tree`); `vm/guest/run-app.ps1`
(`Resolve-Installer` and its callers); `docs/DECISIONS.md` M1b rows of 2026-11-18; `vm/RIG.md` 12.5;
`vm/truth/labels/python.json`; `kb/shared-components.json`.

Runs:
- `bash truth/m1b.sh --selftest`: 0 failures; `git status` clean before and after.
- `rigtool score` (the binary in the tree) on a scratchpad copy of `vm/runs/m1b-python` with the Launcher
  suggestion added to the plan (B1).
- `rigtool ambient` over the three null-run sets into the scratchpad, and a Python emulation of the two new
  folder rules over those sets, every frozen truth and every archived run truth (section 2).
- `m1b.sh`'s `target_entry` (lines 181-210, copied out) on the archived run records (RUN, S2).
- Reads of the archived snapshots, lists, plans, scores and budget logs.

Not run: any cargo test (the new engine and rigtool tests were read, not run), `rig-selftest.ps1`, the
engine itself. The engine's band for the suggestion in B1 is from reading, not from a run.

## Blocking

### B1. The Launcher suggestion fails K1, K5 and K6 for `python` (clean and CleanPro)

`crates/purge-scan/src/sys_burndeps.rs:467-489` (`suggestion`), `vm/rigtool/src/score.rs:869-873`,
`:1101-1107`, `:405-409`, `vm/truth/labels/python.json:56`.

The new rule lists the Launcher's Uninstall key
`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73831AC2-...}` as `ReportOnly`.
The label file labels that key `kept_owner`. rigtool decides "danger" from the target alone, whatever the
action, and counts a report-only item as a listing for `protected_correct` (its doc says so).

The item will not be Blocked (reading):
- `suggestion` attaches no blocker (no `common_blockers`).
- `ScanCtx::run` adds `msi_blockers` only: for a key, the MSI Registry rows at or below it. The Launcher
  package has none under its Uninstall key (`msi-tables-m1b-python-2.json`: no row names `Uninstall`).
- The plan's deny list does not read `kb/shared-components.json` (only SYS-BURNDEPS and the Burn harvest
  do), and `reg.uninstall` covers the container key only.
- The policy gives a `ReportOnly` item Likely or Weak, never Safe.

Experiment: the archived `m1b-python` plan plus that item, scored with the tree's rigtool against the run's
own truth:

| band given | danger_offered | danger_kept | protected_correct |
|---|---|---|---|
| Likely | 1 | 1 (bam) | 28 of 29 (96.55 %) |
| Weak | 1 | 1 (bam) | 28 of 29 |

Failure scenario: the next campaign shows `K8 G2 clean/python suggestion: 1 ... PASS` and, for the same
run, `K1 G2 clean/python: danger_offered=1 FAIL`, `K5 ... FAIL`, `K6 ... FAIL`. The same three on
`cp/python` (G8). Dirty is not affected (no suggestion there, see B2).

This is a conflict between criteria, not an engine fault: K8 wants a report-only line on a key that K1 and
K5 say must not be listed below Protected. It needs a ruling. The options seen:
- the engine lists the suggestion Blocked with a blocker that says "still installed, uninstall it
  yourself" (K1 then counts it `danger_kept`, K5 and K6 pass, K8 passes on the action); the 2026-11-18 K1
  row names "Blocked for a reason other than a deny-list hit" as its reversal condition, so the row
  would need a word on it;
- or rigtool treats a `ReportOnly` item as neither an offer nor a listing (its own `removes()` already
  says it removes nothing), which changes K5's documented meaning.
Either is an engine or scorer change and needs its own review.

### B2. K8 asks for the suggestion on dirty-base, where other Pythons are installed

`vm/truth/m1b.sh:1097-1104`, `vm/guest/setup-dirty.ps1:77-78`, `docs/M1B_DESIGN.json` K8.

K8 runs `python suggestion: >= 1, all ReportOnly` for `clean` and `dirty`. dirty-base holds Python 3.13.1
and Python 3.11.9 (experiment: `lists-m1bd-python-0.json` and `-2.json` list both bundles and
`Python Launcher 3.13.1150.0`, product `{7102CAE5-...}`).

On `m1bd-python` the new rule gives no suggestion, twice over, and rightly:
- the Launcher is 3.13.1's, its `LastUsedSource` is `...v3.13.1150.0`, the 3.12.7 bundle does not link it;
- `CPython-3.11` and `CPython-3.13` are still registered, so `family_left` is true.

Failure scenario: `K8 G3 dirty/python suggestion: 0 suggestion(s) FAIL` again, with a correct engine. The
design's wording is "python (alone)"; on dirty-base it is never alone. The same reasoning as the node
ruling applies: the dirty python run is a good negative case (expect 0), not a positive one. Needs a
ruling and a change of `m1b.sh` (and its fixture, which has the suggestion on dirty).

### B3. K14 "warm MSI table cache" cannot pass: the cold scan round is warm

`vm/rig.ps1:1415-1437`, `vm/truth/m1b.sh:1320-1343`, `vm/truth/m1b-fixture.py:210`, `vm/RIG.md` 12.5.

`Invoke-M1bBudgets` moves the cache aside once, before round 1 of the M1b engine, then runs `harvest` and
`scan` of that round one after the other. The harvest builds the ownership index with the disk cache and
writes every package it reads (`purge-index` `ownership.rs:1461-1468`); the scan reads the same 313
packages (archived logs: both steps `sys.msi_tables 313/140094`). So with a working disk cache the round 1
scan has 313 hits and no `sys.msi_tables` in its total line.

`m1b.sh` then reports, for step `scan`:
- `m1b scan cold: read no sys.msi_tables (nothing to be warm against)` (line 1325);
- `m1b scan round 2 / 3: read 0 sys.msi_tables, the cold round 0` (line 1342).

The fixture hides it: `budget_log` gives every cold log 313 reads, the scan too. (Reading; the failed
campaign cannot show it, its cache was in memory.)

Failure scenario: G7 is run exactly as documented, elevated, with the data root in place; the harvest
lines pass and `K14 G7 warm MSI table cache` FAILs with three problems for `scan`.

Fix directions: move the cache aside before each cold step, not once per round; or judge the scan's
warm rounds by the cache line alone and compare reads for the harvest only. The first keeps "cold scan"
meaningful for the existing `added scan time (cold)` and `ownership.tables (cold)` lines, which today
would also measure a warm scan.

## Should fix

### S1. The rigtool binary in the tree does not have the ambient folder rules

`vm/truth/m1b.sh:60`, `vm/rigtool/src/ambient.rs:114-150`.

`vm/rigtool/target/release/rigtool.exe` is dated 2026-11-18 04:06; the folder rules were committed at
11:05. Experiment: `rigtool ambient` over `m1bd-null1..3` with that binary gives 90 patterns, none of them
a folder rule. `m1b.sh` records the binary's SHA-256 in the manifest but nothing ties it to the source.

Failure scenario: the campaign is scored without rebuilding rigtool; `dirty/temurin` again has 2 leftover
truth items (`%TEMP%\6194.tmp`, Steam's `service_log.txt`) and an empty plan, K2-K6 FAIL as before.
Rebuild rigtool before `collect`; better, have `collect` refuse a binary older than
`vm/rigtool/src` or record the rigtool commit.

### S2. A trap run without a pre record passes RUN

`vm/truth/m1b.sh:205`, `:728-730`; DECISIONS 2026-11-18 ("the pre record is missing" is invalid).

`target_entry` sets `main_is_pre = any(same(e) for e in pre_e)`. With no `pre` in run.json the list is
empty and the value is `False`, never `None`, so the check "cannot tell whether the target is TrapA (no
pre record)" cannot fire on a real record. Experiment: the function on `m1b-traps-7zip/run.json` with
`pre` removed gives `main_is_pre: False, pre_keys: []`. The control `trap_no_pre_record` sets
`main_is_pre=None` in the collected record, a state `runsum` never writes.

Failure scenario: a trap run whose pre-app phase recorded nothing passes RUN. K9 still wants TrapB node,
so the gate does not pass on it; the ruled check is simply not there. Fix: `None` when `pre_e` is empty,
and build the control from a run.json without `pre`.

### S3. K1 and K8 accept a Blocked danger item whatever blocked it

`vm/truth/m1b.sh:942-957`.

The ruling's case is a deny-listed hit (`DenyListed reg.hklm.system`), and its DECISIONS row names
"Blocked for a reason other than a deny-list hit" as what would reverse it. The check reads only the
band. The note names target and scanner, not the blocker.

Failure scenario: a later engine lists a danger item Blocked through `NotGone` or `TooLarge` (states
that can change between scan and execute); K1 passes with `danger_kept=1` and the report does not show
that the ruling's condition is not met. On the archived scores every kept item is the bam value
(experiment), so nothing is wrong today. Fix: read the item's blockers from `<set>-<id>-scan.json` and
put them in the note, or fail unless one is `DenyListed`.

### S4. The shared ownership index changes co-product harvests, and no test covers it

`crates/purge-harvest/src/harvest.rs:280-282`, `coproducts.rs:125`,
`crates/purge-harvest/tests/m1b/coshared.rs:71`.

A candidate's harvest used to build its index from the entries alone; it now gets the engine call's
index, `msi_only` rows included. The test that claims "byte for byte" asserts `doc.msi_only.is_empty()`
first, so it compares the two only where they cannot differ.

Direction of the change (reading):
- more products known as component clients: more `other_clients`, more kept. Safe direction.
- `ix.installed()` is true for more products in the Burn harvest of a candidate (`burn.rs:369`, `:402`):
  the foreign-product check catches more (safe), and a package product without an Uninstall key can now
  become a child of a co-removed bundle, as it already does when that bundle is the target.

Nothing here reaches further than a target harvest of the same product already does, so it is not a
safety finding. It is an untested behaviour change in what a co-removed product claims. Add a fixture
with an `msi_only` product that is a client of a candidate's component, and one that is a candidate
bundle's package, and state the result in the test.

## 1. Engine safety (focus 1)

Checked, no finding:

| Question | Result |
|---|---|
| Can the linked rule emit anything but `ReportOnly`? | No. `burn.linked` is read in one place (`sys_burndeps.rs:178`), which builds only `suggestion`. `fs_pkgcache` does not read it, so the Launcher's Package Cache folder is not offered through it. |
| Can the item become executable later? | The policy never gives `ReportOnly` Safe; the executor refuses it (`cli/exec.rs:611`); a merge with a deleting candidate on the same key would drop the suggestion's evidence, and no scanner offers another product's Uninstall key. |
| Forged per-user bundle named `CPython-*` | The link needs machine records only administrators write (UpgradeCodes, machine install, machine `SourceList`) and a `BundleVersion` equal to the folder's. A forged bundle that copies the version gets a suggestion only when no CPython provider key is in any hive and every profile is loaded, when the suggestion is true anyway. Report only. |
| Unloaded hive, unknown profiles, incomplete Burn index | `family_left` returns `None`, no suggestion, a scan warning. The profile list includes S-1-5-18/19/20, whose hives are always loaded; on the rig VMs the list is those three and `tester` (snapshots), so the check does not block K8 on rig-base. |
| Launcher of another version | Not linked: the folder name must end in the bundle's own version. `python312-with-313`: Launcher `{8078A005-...}v3.13.17150.0`, bundle 3.12.7150.0, no link, no suggestion (K8 expects 0). `python313-with-312`: linked, but `CPython-3.12` remains, no suggestion. |
| Real records match the code | Snapshots of `m1b-python` and `m1bcp-python`: `BundleProviderKey CPython-3.12`, `BundleVersion 3.12.7150.0`, Launcher `LastUsedSource n;1;C:\ProgramData\Package Cache\{73831AC2-...}v3.12.7150.0\`, the user's `Dependencies` empty after the uninstall. The suggestion will appear on both. |
| Index reuse across target and candidate | `OwnershipIndex::build` and `sysobj_index::build` take no target. `SharedIndexes` lives for one `harvest_report_with` or one `uninstall` call; in `uninstall` the candidates are harvested (and the cells filled) before the uninstaller runs and the value is not used after. No holder outlives an engine call. |
| Table cache key | Unchanged (`local_package`, size, mtime). `CountingCache` only counts. |
| `harvest_candidate` now calls `harvest_report_with` | Same as `harvest` (which is `harvest_report(...).fingerprint`). |

## 2. Scorer (focus 2)

- **K1 / K8 vcredist**: missing or non-integer counts, a missing list, or counts that disagree with the
  list fail. A band spelled `Protected` would count as offered in `m1b.sh` and kept in rigtool, so the
  counts disagree and the line fails (closed). On the archived scores the four failed K1 lines and the two
  K8 vcredist lines become `danger_offered=0 (danger_kept=1)`, each the bam value, Blocked, REF-ANY.
- **RUN**: applied to all 22 archived app and trap records (experiment): only `m1bd-node` is invalid
  (`in_lists0` true, 0 entries created). Unreadable lists-0, no `main`, no `entries_created` fail. See S2.
- **Ambient folder rules** (experiment, emulated; the binary is stale, S1):
  - rig-base and CleanPro null runs give no folder rule at all;
  - dirty-base null runs give one for `C:\Users\tester\AppData\Local\Temp` and one for
    `C:\Program Files (x86)\Steam\logs`;
  - no item of any frozen truth matches either;
  - on the archived dirty run truths the only non-ambient items that match are one `%TEMP%\<4 hex>.tmp`
    per run (7zip, node, powershell, python, temurin, vcredist) and Steam's `service_log.txt` (temurin,
    vcredist), all labelled leftover by default. Nothing of a gated app.
- **SANITY (R4d S2)**: as asked. With the folder rules it leaves one soft spot: a frozen leftover with a
  random name that a run labels ambient is now "frozen only" (PASS, in the note), not "relabelled" (N4).
- **BIND**: deny and frozen hashes compared on both sides with the same file set; a missing deny list or
  frozen dir fails.
- **K14**: a missing log, total line, cache line or harvest line fails; `memory` fails. See B3.

## 3. Campaign (focus 3)

- K14 line formats match what the engine prints (archived logs against the regexes): `timing: total:
  ...; sys.msi_tables 313/140094 ...`, `harvest: <name> (<id>); 1 root(s), 0 rejected; ...; 0 co-product
  candidate(s); ...` for both engines; the new cache line is `timing: msi_table_cache disk <dir> hits=N
  misses=M`, which `CACHE` and the `hits=` search read.
- `Get-M1bGateApps -Base dirty-base` and `DEF_DIRTY_APPS` are the same seven ids in the same order;
  `M1B_DIRTY_APPS` is a gate variable, so another list makes the configuration custom.
- `install.ps1` verdict: `Test-Tree` checks the six layout objects and reparse points two levels down.
  `fp\msitables` and its files are not layout objects, so a filled cache keeps the verdict `good`.
  `%ProgramData%\Purge` does not exist on this host now: `install\install.ps1` has to run elevated first
  (it also deploys the engine to Program Files).
- `run-app.ps1` S4: every caller either uses `Resolve-Installer`'s return value or reads the record after
  it, so the new "no installer" throw cannot hit a run whose setup passed.

## Notes

- **N1** `rig.ps1:1394-1398`: unelevated, the verdict is `reject` (users have no READ_CONTROL on the data
  root), and the message says to run install.ps1. It should say that `m1b-budgets` itself must run
  elevated; the engine also needs elevation to recreate `fp\msitables` after it was moved aside.
- **N2** `m1bd-python313-with-312`: installing 3.13.17 replaces dirty-base's 3.13.1 and the uninstall
  leaves no 3.13 (lists-0 against lists-2). RUN passes (another key). It is an upgrade-and-remove case,
  close to what the node ruling excluded; it passed every line last time.
- **N3** After `m1b.sh replay`, the tracked `truth/m1b-replay-diff.json` must not be restored or
  re-checked-out before `collect`: BIND now compares its bytes with the hash in the replay block. R4d's
  "restoring it alone is harmless" no longer holds.
- **N4** SANITY "frozen only" with only ambient run items of the same normalised name deserves a look in
  the gate report whenever its count is not 0.
- **N5** `kb/shared-components.json` lists the Launcher's files and keys by two product codes (3.12.7 and
  3.13.1). The 3.13.17 Launcher is `{8078A005-EBA5-4E1A-9AAF-EC4693A1D7C3}`; the Burn link finds it by
  UpgradeCode, the key and path patterns do not. Not in this diff.
- **N6** `pipeline.rs:537`: `uninstall` builds the shared indexes without the table cache, so the
  candidates' index reads every package from the source. Cost only.
- **N7** The temp rule would hide an app's own `<hex>.tmp` in the user's `%TEMP%` on a base whose null
  runs show one (DECISIONS names this as the reversal condition). No gated app leaves one today.
- **N8** A suggestion is also given when only a non-Burn Python (2.7, 3.4 MSI) remains, which `py.exe`
  can still start. Report only.
