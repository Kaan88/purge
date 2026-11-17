# M1b review R4c: smoke fix, scorer, truth

Reviewed at `b1fcd97` (head of local `m1b`). Reviewer changed no source code.

Scope: the commits since R4b (`de003c2`): the svchost smoke fix (`824b744`), the
R4b scorer fix (`c226f5e`), and the truth work (`805477a`, `b1fcd97`).
Not reviewed: the local-baseline design (`5cb7f96`, `99db78e`), which is post-M1b.

## Verdict

**No blocking finding.** The engine fix holds: no svchost-hosted service found
that can still be recorded, offered or deleted, and an app's own service with
its own exe is judged as before. The scorer now fails closed where R4b showed
it passing wrongly. The truth changes all push in the strict direction: no way
was found for the noise list, the ambient rules or the pre-state items to make
K1 or K4 pass more easily.

What is left is about what the gate proves, not about safety:

- Five trap verdicts the design names were changed with no ruling in
  `docs/DECISIONS.md`, and one of them hides an engine limit (S1).
- The gate cannot pass G1 as scripted: nothing writes the replay score (S2).
- The trap and label files are not bound to a commit (S3).
- Nothing compares a gate run's truth with the frozen truth (S4).

**Ready for the gate: yes, after:**

1. S1: one `docs/DECISIONS.md` row for the five changed trap verdicts, and
   `msi-remnants` changed from `absent` to a verdict that does not punish a
   correct offer.
2. S2: a command that writes `truth/m1b-replay-score.json`, with the five
   replay apps required.
3. S3: `vm/truth` and `vm/guest` clean against HEAD, checked by the script or
   stated in `M1B_GATE.md` with the hashes.
4. `cargo xtask ci` passes once from an unelevated shell (open since R4).

S4 can be met in the gate report. Items 1 to 3 are a few lines each and need
no VM run.

Evidence labels:

- **experiment**: a run against this commit on this host (Windows 11 26300,
  elevated shell, `CARGO_TARGET_DIR=E:\purge-build\review-r4c`, deleted afterwards).
- **reading**: confirmed by reading the code or the recorded evidence; no run.
- **suspected**: not confirmed.

## Reviewed

Read by the reviewer, no delegation: the three diffs, `purge-index/src/sysobj.rs`
(service facts, `command_exe`, `resolve_program`, `Env`), `purge-guard`
`deny/objects.rs` and `canon.rs`, `purge-exec/src/act_service.rs` (program,
gate), `purge-harvest/src/sysobj.rs`, `purge-scan` `sys_service.rs` and
`framework/m1b.rs` (`object_guard`, `product_known_in`), `vm/truth/m1b.sh`
(all stages), `m1b-traps.json`, `_m1b-noise.json`, the two Python pair label
files, `frozen/powershell` and `frozen/temurin`, `FROZEN.md`, `vm/RIG.md`
section 12, `vm/rigtool/src` `traps.rs`, `truth.rs` (label order) and
`score.rs` (outcome, precision), the `rig.ps1` and guest diffs, and the smoke
evidence in `E:\purge-build\gate-evidence\m1b-smoke-7zip\after` (plan, probe log).

Runs (all passed):

- `bash truth/m1b.sh --selftest`: 0 failures (2 base tests, 40 controls, 14
  configuration tests, 4 churn tests, the pre-state test, 2 trap file tests).
- `cargo test`: `purge-guard --lib deny::objects` (2), `purge-scan --test
  sys_service` (20), `purge-harvest --test m1b sys_service` (4), `purge-exec
  --features test-support --test act_service validate_` (11), `xtask
  replay_diff` (1).
- No ignored test, no rig test, no VM, nothing that changes system objects.
- Not run: `cargo xtask replay-diff` (R4b reproduced the file; the diff since
  is the schema and the `justified_promotions` list).

## 1. The svchost fix (824b744)

**Sound (reading, experiment on the tests).** A service is svchost-hosted when
the file its `ImagePath` runs is named `svchost.exe`. For such a service the
guard gets the raw `ImagePath`, and `sys.service.windows` judges it lexically.
The same rule is applied in three places: the scan sealing
(`ScanCtx::object_guard`), harvest (`record`) and the executor gate
(`guard_program_text`, its own copy of the logic).

The program becomes the `ServiceDll` only when the host canonicalises to
`%SystemRoot%\System32\svchost.exe` or the `SysWOW64` one. So the question is
whether a raw `ImagePath` can canonicalise to that file and still not read as
under `%SystemRoot%`.

| Attack | Result |
|---|---|
| Own group, shared group, `-k X -p` | Blocked. The arguments play no part (experiment: both test images). |
| `ServiceDll` under `Parameters`, or under the service key | Blocked. The DLL is no longer what the guard reads. |
| `ServiceDll` in the app root, DLL present or gone | Not recorded, not listed. With a forged or older harvest record: listed Blocked (experiment). |
| `%SystemRoot%`, `%windir%`, `\SystemRoot\`, `System32\...`, `\??\`, `\\?\`, quoted, forward slashes | Blocked. Each form is in `under_system_root`; a leading quote is trimmed. |
| Any other leading `%VAR%` (`%SystemDrive%\Windows\...`) | Blocked. An unknown first segment counts as relative, which counts as under the Windows directory. |
| `SysWOW64\svchost.exe` | Blocked. |
| Windows directory not `C:\Windows` | Blocked. All three callers use `DenyList::check_object`, which knows the real directory. |
| `..` segments, short names, `\\.\`, UNC, a junction to the Windows directory | Not the system host: `canon_path` refuses them or the path is not equal. The program is `Unresolved`, never evidence, never Safe. |
| A file named `svchost.exe` in the app's folder | Not blocked by the guard, program `Unresolved`. Same as before the fix. |
| `dllhost`, `rundll32`, `taskhostw` and other hosts as `ImagePath` | Program `Unresolved` (`is_host`), so not recorded and not Safe. The executor passes the raw text, which is under `%SystemRoot%`: blocked. Unchanged. |
| An app's service with its own exe | Unchanged: `guard_program` returns the resolved file, as before. |
| Deleting through the registry instead | `reg.hklm.system` blocks every key and value under `Services` (smoke plan: all REF-ANY entries there are Blocked). |

One residual, not worth a fix before the gate (M1).

### The six trap changes

| Case | Change | Judgment |
|---|---|---|
| svc-svchost | absent to protected | **Design rule.** C-GUARD says such a service is "never offered as a typed target". The Blocked REF-ANY entry for `Parameters\|ServiceDll` is not an offer. Under `protected`, any actionable entry on or inside the service still fails. Written up in `DECISIONS.md`. |
| wer-twins (7zFM report) | listed to protected, `DenyListed` | **Design rule.** The FS-WER module says reports in `%ProgramData%` stay denied by `fs.programdata.microsoft`. Smoke plan agrees. |
| svc-owned, task-owned, fw-owned, com-owned | safe to listed | **The design contradicts itself; the engine is right.** The design's plant is "a copy of an exe inside TrapA's install folder", which keeps the root alive, and D10 needs the whole root gone for Safe. But see S1. |
| msi-remnants | safe to absent | **An engine limit, relabelled.** See S1. |

## 2. The R4b scorer fix (c226f5e)

| Id | Status | Note |
|---|---|---|
| B1 | fixed (experiment) | Schema `/3`. K16 judges rows, recomputes promotions, needs the five apps and exactly five reasons. Eight controls. A new item offered Safe is not a promotion; K4 on the replay covers it. |
| B2 | fixed by ruling | See below. |
| S1 | fixed (experiment) | K9 needs the planted record, every case ok, every target planted. A failed plant phase ends the run. Seven controls. |
| S2 | partly | RUN and BIND rows, build record per run, empty plan fails. Not bound: the trap and label files to a commit (S3), the replay score (S2 below), the null runs. |
| S3 | fixed (experiment) | Exit 3 for `--evaluate` and every non-default setting. 14 tests. |
| S4 | fixed | Generic launcher rules, and the freeze was run. The Microsoft Update opt-in was real and is kept_owner. |
| S5 | fixed | Pre-state kept_owner (section 3). |
| S6 | fixed (selftest) | 12 runs, exit codes, round kinds, `cold_cache_state`. |
| M1 | not done | S2 below. |
| M2 to M5, M8 to M10, M12 | not done | Minor, as before. |
| M6, M7, M11 | fixed | 7-Zip needs a Safe item on rig-base; RIG.md 12.1 names `-Nulls`; `kb` is in the clean check. |

Nothing was made worse.

**The B2 ruling.** K6 now counts only a band that offers or preselects
wrongly. A true leftover at Weak or Blocked is a recall miss, reported in the
note.

- Consistent with M1a: that gate counted such items in recall
  (`recall_visible_nd`), never as a band mismatch.
- Not consistent with the design's K6 text ("leftover: Safe or Likely"). The
  ruling is in `DECISIONS.md`; the design text was not changed (M2).
- It is broader than R4b proposed. R4b kept a leftover below Likely as a
  mismatch for M1b scanners. With the ruling and the `listed` verdicts of S1,
  no criterion of the scan gate asks an M1b scanner to reach Likely on
  anything but 7-Zip's `Software\7-Zip` key (K7). That is a recall question
  and safe, but the gate report should say it.

## 3. Truth (805477a, b1fcd97)

**Can the noise list or an ambient rule make K1 or K4 pass too easily? No (reading).**

- Danger does not come from labels. It comes from snap 0, lists-0, the rig's
  deny list and kept_owner items (`score.rs:860-900`). An ambient label
  removes none of the first three.
- An item labelled ambient and offered Safe counts against precision: it is
  in `safe_not_gone` and is not a hit (`score.rs:1035-1043`). Without the
  noise list the same item would default to leftover and score as a hit. So
  the list makes K4 stricter.
- The one loose direction: ambient comes before kept_owner and user_data in
  the label order (`truth.rs:391`), so a noise rule could take away a
  "covers kept_owner" danger. RIG.md 12.6 says otherwise (M3). No rule does
  this today: all 17 lie under Windows-owned keys and folders, none overlaps
  a kept_owner or user_data rule of the Python pair or PowerShell label
  files, and the selftest checks them against every frozen truth.
- `Installer\TempPackages`: a package it names is relabelled ambient unless
  snap 2 names it as an installed product's `LocalPackage`. A kept launcher's
  cached package keeps its label.
- One-run-only items are left out of the frozen truth and listed. Both
  freezes excluded 0.

**Pre-state kept_owner: right for what it labels (reading).**

- Only objects in snap 0 and in snap 2 that a rule matches. Product rules
  apply only to an ARP entry named exactly "Python Launcher" with the same
  product code in both lists.
- An object that holds a leftover or user_data item is opened to its
  children, not labelled whole.
- Every such object is danger already if offered (it is in snap 0), so the
  items change K5's count and nothing else. The count is honest: 36 launcher
  objects plus 6 shared containers, and 20 plus 24.
- The generic rules of `python313-with-312` also label a stale record of the
  removed 3.13 as kept_owner. That can fail K1 on a correct offer. It cannot
  pass a wrong one.
- 42 and 44 come from one campaign with a custom ambient set. Not reproduced
  here (the runs are not on this host).

**The frozen truths are plausible (reading).**

- PowerShell, 9 leftover: the `PowerShellCore` key, five event-log
  registration keys, `%LOCALAPPDATA%\Microsoft\PowerShell`, the Prefetch file,
  one UserAssist value. 2 kept_owner: the Microsoft Update opt-in. Among the
  205 ambient items the only PowerShell traces are the `BreadcrumbStore` files
  (a denied Windows store) and a `bam` record (report-only).
- Temurin, 0 leftover: not launched, and the MSI removes what it installed.
  None of the 101 ambient items names Java, the JDK or Adoptium.

## Blocking

None.

## Serious

### S1. Five design verdicts changed without a ruling; `msi-remnants` hides an engine limit (reading)

`vm/truth/m1b-traps.json`, `vm/RIG.md` 12.3, `docs/M1B_DESIGN.json`
(M1B-RIG-HOST: "owned objects ... verdict safe"), `framework/m1b.rs:587`.

- The design names `safe` for svc-owned, task-owned, fw-owned, com-owned and
  msi-remnants. K9 asks for missed_owned = 0 against those. The reasons are in
  RIG.md only. `DECISIONS.md` has a row for svc-svchost and none for these.
- `listed` passes at Weak. The smoke run had the four at Likely, but the gate
  would not notice a drop.
- Safe for a service, task and firewall rule is still shown at G5
  (`m1b-exec.sh` fails a case that is "not offered Safe"). Safe for a COM
  class and for an MSI registration is shown on no VM.
- **msi-remnants.** The plant is the key the scanner is for:
  `UserData\S-1-5-18\Products\<P>` with `InstallProperties`. That key alone
  makes Windows Installer report state 2, for 7-Zip's code and for the made-up
  code alike (`msi-state-probe.log`). `product_known_in` treats every state
  but unknown as known. So REG-ARP-MSI cannot offer this key while its
  `InstallProperties` is there, which is the usual shape of the remnant.
  This is safe, and it is a recall limit of the engine, not a design rule.
- `absent` is the wrong verdict for it: the case is now the same as
  msi-remnants-foreign, and a later engine that offers the app's own remnant
  correctly would score an escape.
- Fix: one `DECISIONS.md` row that names the five changes, the reason for
  each, and the REG-ARP-MSI limit as a known gap. Change msi-remnants to
  `not_preselected`, or drop the expectation and say so. Have `M1B_GATE.md`
  list the band of the four owned objects.

### S2. G1 cannot pass as scripted: nothing writes the replay score (reading)

`vm/truth/m1b.sh:69, 792-806`.

- K4 and K7 for G1 read `truth/m1b-replay-score.json`. The file does not
  exist, no script or xtask writes it, and RIG.md does not say how (R4b M1).
- A hand-made file is bound to no engine and no commit.
- K4 loops over whatever apps the file holds. A file with 7-Zip alone passes.
- Fix: one command (replay the five frozen runs, then `rigtool score`), and
  require the five `REPLAY_RUNS` in the file.

### S3. The trap and label files are not bound to a commit (reading)

`vm/truth/m1b.sh:682-690`, `vm/rig.ps1` (`Get-M1bBuildInfo`).

- BIND compares the hashes at collect with the hashes at evaluate. In a gate
  run the two follow each other, so they are always equal.
- The source-dirty check covers `crates bins tools kb` and the Cargo files.
  It does not cover `vm/truth`, `vm/guest` or `vm/rig.ps1`.
- So an uncommitted edit of `m1b-traps.json`, a label file, the noise list or
  a plant script gives a gate PASS. The hashes are in the score, but nothing
  compares them with HEAD. The trap file was edited in the same commit as the
  engine fix, so this is the case to guard.
- Fix: in collect, fail BIND when `git status --porcelain -- vm/truth
  vm/guest vm/rig.ps1` is not empty; or compare each hash with `git show
  HEAD:<file>`.

### S4. A gate run's truth is never compared with the frozen truth (reading)

`vm/truth/m1b.sh` (collect, FROZEN row), `docs/M1B_DESIGN.json` G2.

- The design says the runs are "scored against frozen truth". Each run is
  scored against its own diff. FROZEN only checks that the two files exist.
  `m1a.sh` had a sanity step for this; `m1b.sh` has none, for any of the
  eight apps.
- A run whose launch did nothing, or whose uninstall removed more or less
  than usual, has a different truth and is scored without a word. With fewer
  leftovers K4 can be null, which passes for every app but 7-Zip on rig-base.
- The other direction fails closed: churn in a Temurin run gives leftovers
  where the frozen truth has none, and a correct empty plan then fails as
  "empty plan".
- Fix: print each run's label counts beside the frozen counts and fail, or
  ask for a written acceptance, when leftover plus user_data differ. At the
  least, put that table in `M1B_GATE.md`.

## Minor

- **M1 (reading).** The svchost guard reads the raw `ImagePath`; the index
  expands variables first. `C:\%X%\System32\svchost.exe` with a machine
  variable `X=Windows` is the system host for the index and not under
  `%SystemRoot%` for the guard. It needs an administrator to set that
  variable. Passing the expanded host path would close it.
- **M2 (reading).** K6 in `M1B_DESIGN.json` still has the old text. Point it
  at the ruling.
- **M3 (reading).** RIG.md 12.6: "it can only take an item out of the
  leftover set" is not what `truth.rs` does. An ambient rule also wins over
  kept_owner and user_data. The selftest check covers the frozen truths only,
  not the Python pair truths.
- **M4 (reading).** svc-svchost `protected` names no blocker. `DenyListed`
  would pin it.
- **M5 (suspected).** A svchost service of a removed app is now never
  offered, but FS-INSTALLDIR can still offer the folder that holds its DLL.
  The service then stays registered with no DLL, and no later run can remove
  it. Harmless to Windows; worth a report-only line.
- **M6 (reading).** The frozen truths rest on one null run per round. The
  gate sets use three.
- **M7 (reading).** RIG.md 12.3 still opens with "The gate should check them
  (UNSURE)" above a list the smoke run has since settled.
- **M8 (reading).** `purge-exec` builds with 3 warnings in the test profile.
  Check that G0's `clippy -D warnings` still passes.
