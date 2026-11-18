# M1b review R4d: the R4c fix round and the guest hash check

Reviewed at `59ac127` (`git diff 7d3ffa4..59ac127`: `abe3645` and `59ac127`), with the working tree at
`ee43fa2` while a gate campaign was running. Reviewer changed no file in the repository, built nothing and
ran no VM.

## Verdict

**No blocking finding. Nothing found invalidates or will falsely fail the running campaign, as long as the
three rules under "Running campaign" are kept.**

- The four R4c findings are fixed as asked and no criterion was loosened. The `msi-remnants`
  `not_preselected` ruling is sound.
- The scorer fails closed for a missing or odd replay score, rig-input record and run truth. No way was
  found to get a K line to PASS or exit 0 from a missing input.
- The CRLF rewrite of `m1b-replay-diff.json` and the untracked `m1b-replay-score.json/.md` trip neither
  dirty check (experiment).
- The guest hash check works for the case it was written for. One path still runs a wrong installer, but
  the run is then failed, not scored (S4).

What is left:

- S1: `truth/deny.json` and the frozen truths of five apps are still bound to no commit (R4c S3 half done).
- S2: SANITY can fail a correct run when an unrelated ambient item shares a normalised name with a frozen
  leftover (python, vcredist `%TEMP%\<rnd>.tmp`). This is the one realistic false FAIL. It costs a
  re-score, not a campaign.
- S3: the replay diff (K16) is not bound to the replay, and a failed `replay-diff` leaves the committed
  file in place.
- S4: on a pin mismatch after the second download, the main app's install phase still runs the file.

Evidence labels: **experiment** (a read-only command on this host), **reading**, **suspected**.

## Running campaign

State seen (experiment, read-only): runs `m1b-null1` and `m1b-7zip` whole (13 and 21 phases ok), the two
Python runs in progress, no `m1b-build.json` yet (they are written when the `rig.ps1` invocation ends).
`m1b-replay-score.json` holds the five runs, `danger_listed` 0 each, `precision_safe` 1.0 (npp null), a
`replay` block for `ee43fa2`, `source_dirty` false. The replay diff equals the committed one apart from
line endings.

Both dirty checks, run as `rig.ps1` and `m1b.sh replay` run them, print nothing now:

- `git status --porcelain -- vm/truth/m1b-traps.json vm/truth/labels vm/guest vm/rig.ps1`
- `git status --porcelain --untracked-files=no -- crates bins tools kb Cargo.toml Cargo.lock rust-toolchain.toml`

The modified diff file and the untracked score files are outside both path lists. Collect reads the diff
as JSON, so its line endings play no part.

Rules until `bash truth/m1b.sh` has printed its result:

1. **No commit** (not this review, not the replay score) before the last `rig.ps1 -Mode m1b-apps` /
   `m1b-traps` invocation has started. Each invocation records HEAD at its start; BIND wants one commit
   over all runs, and the replay block names `ee43fa2`. A docs-only commit in between fails BIND.
2. **No git command that rewrites working files** under `vm/truth/labels`, `vm/truth/m1b-traps.json` or
   `vm/truth/frozen` (`reset --hard`, `checkout -- .`, a branch switch and back). The hashes are of the
   working bytes; 10 of the 30 files sampled are LF in the working tree with `core.autocrlf=true`, so a
   re-checkout turns them into CRLF and BIND then reports changed trap, label or frozen files.
   Restoring `m1b-replay-diff.json` alone is harmless.
3. **Do not edit a label or trap file to fix a scoring problem.** Since R4c S3 the files scored with must
   be the files the runs saw; a label fix means a new campaign. A fix to `m1b.sh` itself does not (see S2).

Also: an interrupted `rig.ps1` invocation leaves its finished runs without a build record (N3).

## Reviewed

Read: the full diff; `vm/truth/m1b.sh` whole; `vm/rig.ps1` (`Get-M1bBuildInfo`, `Get-M1bRigInputs`,
`Save-M1bBuildRecords`, `Invoke-M1bEngineCampaign`); `vm/guest/run-app.ps1` (`Resolve-Installer`, the
setup, pre-app and install phases); `vm/guest/riglib.ps1` (`Phase`, `Fetch`, `Test-InstallerFile`);
`vm/guest/apps.ps1`; `vm/guest/setup-dirty.ps1`; `vm/guest/null-run.ps1`; `vm/rigtool/src/traps.rs`
(verdicts, report fields); `tools/xtask/src/replay_diff.rs` (`run`); `docs/DECISIONS.md` M1b rows;
`vm/RIG.md` section 12; `docs/M1B_DESIGN.json` gate text; the six frozen truths SANITY reads;
`labels/_m1b-noise.json`; `vm/cache/inst/cache-sources.json`.

Runs: `bash truth/m1b.sh --selftest`: 0 failures. The two `git status` commands above. A read of the
existing run records and the replay score. No cargo, no rigtool, no VirtualBox, nothing under `vm/runs`
or `E:\purge-build` written.

## 1. The R4c findings

| Id | Status | Note |
|---|---|---|
| S1 | fixed (reading) | `DECISIONS.md` row names the five verdicts, the reason for each and the REG-ARP-MSI limit with what would reverse it. `msi-remnants` is `not_preselected`. K9's note prints `owned bands:` for the four. The selftest pins the verdicts. |
| S2 | fixed (experiment) | `m1b.sh replay` writes the score with a `replay` block. K4 G1 needs one purge score per run, all five, and fails on any other app. BIND needs the block, the runs' commit, clean sources and the current frozen truths. The real file passes these checks. Rest: S3, N1. |
| S3 | partly (reading) | Trap file, every label file, the guest scripts and `rig.ps1` are hashed before and after each campaign and checked against HEAD, untracked files included; BIND needs one set, unchanged, clean, equal to the files scored with. Not covered: S1 below. |
| S4 | fixed, lighter option (reading) | SANITY fails a frozen leftover or user_data item the run labels otherwise and reports items on one side only. A run with fewer leftovers than the frozen truth still passes; R4c allowed that if the gate report carries the table. False FAIL: S2. |
| R4b S2 rest | fixed (experiment) | RUN covers the null runs: at least 2 per set, each finished, every phase ok. The real `m1b-null1/run.json` has the fields the check reads. |

No criterion was loosened. K1 to K9, K14 and K16 read as before; the new rows only add FAILs.

**The `msi-remnants` ruling is sound (reading).** `not_preselected` in `traps.rs:447` fails when any
equal, covering or inside entry is preselected or Safe, and passes otherwise, listed or not. So:

- it is stricter than nothing and looser than `absent` only for a Likely or Weak offer of the app's own
  registration, which is a correct offer;
- it stays distinct from `msi-remnants-foreign` (`absent`);
- it is weaker than the design's `safe`: no case now proves that an MSI registration is ever offered.
  The row says so ("Safe for an MSI registration is shown on no VM") and names it an engine gap. The gate
  report must repeat it; K9 PASS does not show REG-ARP-MSI recall.

## 2. Fail-closed

| Input | Missing or odd | Result |
|---|---|---|
| Replay score absent, unreadable, not JSON | `load` gives None | K4 G1 and K7 G1 FAIL |
| Replay score without `replay` block, other commit, dirty, a run short, frozen truth changed | | BIND FAIL (five selftest controls) |
| Replay score with fewer or other apps | | K4 G1 FAIL per run, or `replay apps` FAIL |
| Build record without `inputs`, `inputs_dirty` not false (null when git failed), `inputs_after` differs, two sets, no guest script or no `rig.ps1` in the set | | BIND FAIL |
| Trap or label file edited before the campaign, committed or not | | BIND FAIL (dirty, or differs from the files scored with) |
| Run truth missing for an app with a frozen truth | | SANITY FAIL |
| Fewer than 2 null runs, or a null run not whole | | RUN FAIL |
| Frozen truth of an app missing or not JSON | SANITY row is skipped | no FAIL: N2 |
| Replay diff stale | | K16 PASS on the committed file: S3 |

False FAILs looked for: the key built by `Get-M1bRigInputs` (`vm/` plus the path under `vm`, from
`$PSScriptRoot`) matches the key `m1b.sh` builds; both sides hash the same working bytes; label file
listing agrees (`*.json`, top level); `git status` normalises line endings, so CRLF working files are
clean; the null prefixes `m1b-`, `m1bd-`, `m1bcp-` do not shadow each other. One found: S2.

## 3. The guest hash check (59ac127)

**Correct for its case (reading).**

- A pinned app with no cache entry and a same-named file of another hash: deleted, downloaded again.
  This is the G3 case (`python313.exe` 3.13.1 on dirty-base).
- After the download, or with a cache entry, the hash is compared with the pin once more; a mismatch
  throws. For a pre-app the throw comes before `Install-App`, so nothing runs.
- `-ne` on strings is case-insensitive in PowerShell, so the lower-case pin and the upper-case
  `Get-FileHash` value compare right.
- URLs: python.org, github.com/PowerShell, github.com/adoptium for the three pinned apps. The host cache
  manifest (git-ignored) holds the same three hashes as `apps.ps1` and vendor URLs only (experiment).
- `setup-dirty.ps1` leaves one other name a gate app uses, `node.msi`, from the same URL and version.

Gaps: S4, N4, N5.

## Blocking

None.

## Serious

### S1. `deny.json` and five frozen truths are still bound to no commit (reading)

`vm/rig.ps1:1242`, `vm/truth/m1b.sh:719-761, 797-801`.

- R4c S3 asked for `vm/truth` clean against HEAD. The path list is `m1b-traps.json`, `labels`, `guest`,
  `rig.ps1`. The narrowing is needed (collect writes into `vm/truth`), but it leaves out
  `vm/truth/deny.json`, which `rigtool truth` and `rigtool score` read. The deny list is one of the four
  sources of danger.
- Scenario: an entry is removed from `deny.json` and not committed. A plan item on that path is no longer
  danger, K1 passes, BIND passes: `inputs_dirty` is false and no hash of `deny.json` is taken anywhere.
- Same for `truth/frozen/{python,node,vcredist,powershell,temurin}/truth.json`: FROZEN compares collect
  with evaluate (the flaw R4c S3 described), the replay block covers only the five replay runs. An edited
  frozen truth can only hide a SANITY FAIL, so this half is the lesser one.
- Fix: add `vm/truth/deny.json` and `vm/truth/frozen` to the `git status` path list and to
  `Get-M1bRigInputs`, and compare `deny.json` in BIND as the trap file is compared. Until then: state in
  `M1B_GATE.md` that `git status --porcelain -- vm/truth/deny.json vm/truth/frozen` was empty at collect.
  For the running campaign it is empty now.

### S2. SANITY can fail a correct run on a shared normalised name (reading, suspected for this campaign)

`vm/truth/m1b.sh:809-823`.

- `labs` puts every item of the truth, ambient ones too, under its normalised key, and `relab` fails when
  the run's label set for a frozen leftover key is not equal to the frozen set.
- The frozen truths hold keys that are generic after normalisation: python and vcredist
  `p:c:\users\tester\appdata\local\temp\<rnd>.tmp`, powershell `...\winevt\publishers\<guid>` and
  `...\autologger\eventlog-application\<guid>`.
- Scenario: in the gate's python run the bundle leaves its `.tmp` file (leftover, as frozen) and Windows
  leaves another `%TEMP%\ab12cd.tmp` that the campaign's ambient set labels ambient. The run's set is
  {leftover, ambient}, the frozen set is {leftover}: `SANITY G2 clean/python ... FAIL`, exit 1, on a run
  with nothing wrong. Same if only the ambient file is there (really a "frozen only" case).
- No frozen truth has such a mixed key today, so the two freezes did not hit it. Not shown for the
  running campaign; it depends on what Windows writes during the run.
- The reverse also holds: a real relabel of the leftover is hidden while a second item under the same
  key is still leftover. Weak, but in the passing direction.
- Fix: fail only when the run's set holds neither `leftover` nor `user_data` and the run has an item
  under that key whose own (not normalised) target equals a frozen one, or simpler: compare only the
  non-ambient labels and treat "only ambient in the run" as frozen-only.
- If it fires on this campaign: the runs stay valid. `m1b.sh` is not a rig input, so the fix can be
  committed and collect run again; only label and trap files are frozen by BIND.

### S3. The replay diff is not bound to the replay (reading)

`vm/truth/m1b.sh:1279-1281, 1373`, `tools/xtask/src/replay_diff.rs:405-443`.

- `replay` removes the old score first but not the old diff. `replay-diff` bails before it writes when a
  replay fails, the reference file is unreadable or the runs directory is missing. The committed diff,
  which passes K16 by construction (selftest control `replay_committed_diff PASS`), then stays. `replay`
  exits 1, but collect does not know that, and the score may still be written and bound.
- The `replay` block has no hash of the diff. Scenario: the new engine gives an unexplained row, the file
  is written and K16 would fail; `git checkout -- vm/truth/m1b-replay-diff.json` puts the committed one
  back; K16 passes on a diff this engine did not produce, and BIND has nothing to say.
- Not the case in the running campaign: the file was rewritten by this replay and equals the committed
  one apart from line endings.
- Fix: `rm -f "$REPLAY_DIFF"` at the start of `replay`; put the diff's SHA-256 and the `replay-diff`
  exit code in the `replay` block; BIND compares the hash with `$EVID/replay-diff.json` and needs exit 0.

### S4. A pin mismatch after the second download still runs the installer (reading)

`vm/guest/run-app.ps1:206-208, 382, 441`.

- `$Rec.installer = $file` is set two lines before the throw. For the main app `$Rec` is `$S`. `Phase`
  records the failure and goes on; the install phase checks only `$e.app`, which was set before
  `Resolve-Installer`, and calls `Install-App $a $S.installer`.
- Scenario: the vendor file changed, or the download is damaged but still looks like an installer
  (`Test-InstallerFile` checks the magic bytes and 100 KB). Setup fails with the hash message, then the
  wrong file is installed, launched, uninstalled and scanned for the rest of the run.
- Not silent: the setup phase is `ok = false`, so RUN fails the run and nothing of it is scored. It does
  not match RIG.md 12 ("a mismatch after that fails the phase") in spirit, and it spends a full run.
  The same holds for a post-app (`$r.installer`).
- Also: with a cache entry whose hash differs from the pin, the file is kept and the throw comes without
  a second download. Both hashes agree today.
- Fix: do the pin check before filling `$Rec.installer` (or set it to `$null` before the throw), and
  have the install phase throw when `$S.installer` is empty.

## Notes

- **N1 (reading).** K4 G1 has no empty-plan rule. A replayed plan with 0 items scores `danger_listed` 0,
  `precision_safe` null and passes for four of the five runs (7-Zip is caught by K7). K1 to K6 fail on
  that since R4b S2. `xtask replay` bails when it cannot find the program, so this is unlikely; the real
  file has 139, 4, 21, 3 and 1 offered.
- **N2 (reading).** SANITY skips an app whose frozen truth is missing or not JSON (`m1b.sh:800`). FROZEN
  only checks that the powershell and temurin files have the hash seen at collect. Name the six apps
  (7zip, python, node, vcredist, powershell, temurin) and fail when one cannot be read.
- **N3 (reading).** Build records are written when the `rig.ps1` invocation ends (`rig.ps1:1293-1296`).
  If it is stopped at app 7 of 8, runs 1 to 6 have no record and BIND fails them; they cannot be bound
  afterwards. As R4b built it, but worth a line in the gate handoff: do not stop an invocation, re-run it
  whole if it dies.
- **N4 (reading).** Only powershell, temurin and python313 are pinned. 7zip, python and node have a
  fixed-version URL and no `sha256`; vcredist is `aka.ms`, so its version can differ between the clean,
  dirty and Clean-Pro sets. A same-named older file in a snapshot would again be used without a word.
  `run.json` records `installer_sha256`; the gate report should list it per run. Pin the three.
- **N5 (reading).** 59ac127 adds no test. A Pester case with a wrong-hash file in a temp `$RigInst`
  would have shown S4.
- **N6 (reading).** `replay` reads `source_dirty` after the replays (`m1b.sh:1303`), not before. An edit
  made and undone during the replay is not seen.
- **N7 (reading).** The source-dirty checks pass `--untracked-files=no` and do not cover `vm/rigtool`.
  An untracked file under `kb` or a rebuilt rigtool is not seen. The manifest records the rigtool hash,
  bound to nothing. As before this round.
- **N8 (reading).** The hashes of trap, label and frozen files are of the working bytes, so line-ending
  conversion by git changes them (rule 2 above). Hashing the content with CR removed, or
  `git hash-object`, would take that risk away.
