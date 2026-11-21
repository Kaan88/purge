# M1a gate, campaign `r2-`: score review

Reviewer scope: the numeric criteria of section D and the inventory check of section E. The §1.4 bands are the other reviewer's.

## Verdict

**The numeric criteria pass on the r2 data as captured, and the scoring can be trusted.** Every number below was reproduced: I rebuilt the ambient set, the seven truth sets and the score into a scratch directory with the same scorer binary and got identical items and an identical per-app table.

The pass holds for the binary that ran (`purge-engine.exe` sha256 `1d7524d4cd0c…`, policy `m1a.5` in all seven scan sidecars). It is not yet a gate pass:

- the 11 sanity differences were accepted by the script without anyone looking at them (they turn out to be harmless, see below);
- the m1a.6 re-plan has not been compared;
- the bands review is separate;
- `docs/M1A_GATE.md` still says FAIL.

## Criteria per app

Source for every number: `vm/truth/r2/m1a-score.md`, tool `purge`, per-app table. BCU column: same file, tool `bcu`.

| Run | danger listed / preselected | precision_safe | userdata_presel | recall_visible_nd | Bar | Result |
|---|---|---|---|---|---|---|
| vscode | 0 / 0 | 100.0% (136 of 136 Safe) | 0 | 87.8% (137/156) | > 0% | pass |
| vscode-user | 0 / 0 | 100.0% (143 of 143) | 0 | 88.3% (144/163) | > 0% (VS Code) | pass |
| git | 0 / 0 | 100.0% (2 of 2) | 0 | 23.5% (4/17) | > 0% | pass |
| firefox | 0 / 0 | 100.0% (10 of 10) | 0 | 28.0% (7/25) | > 20.8% | pass |
| firefox-tb | 0 / 0 | 100.0% (8 of 8) | 0 | 31.6% (6/19) | > 20.8% (Firefox) | pass |
| npp | 0 / 0 | no Safe item (`-`) | 0 | 82.1% (23/28) | > 3.4% | pass |
| 7zip | 0 / 0 | no Safe item (`-`) | 0 | 0.0% (0/3) | none written | see below |

- **invdiff:** exit 0 for all 14 run/phase pairs (`vm/truth/r2/m1a-invdiff.md`, `m1a-status.json`). The per-run `invdiff-<n>.md` files show equal counts on both sides.
- **Danger, checked independently of the scorer:** no offered target in any of the seven plans exists in snap0. This includes firefox-tb, where Thunderbird was installed first. No preselected item touches a `user_data` path.
- **Notepad++ precision:** the plan has no Safe item, so "100% on every run" is met only vacuously. Its recall rests on one item, the `AppxPackage` offer (Likely, not preselected), which accounts for 22 of the 23 covered truth items (the other is the `WOW6432Node\Notepad++` key). The package is still registered in `lists-r2-npp-2.json`, so the offer is real. The gate text expects exactly this.
- **Use `visible_nd`, not `recall_listed`:** the babysitter's `recall_listed` figures are higher for Firefox (40.0%), firefox-tb (47.4%) and vscode-user (89.0%). They are not the criterion.

### 7-Zip

The plan is empty (offered 0, truth 3), against BCU's 33.3% on the same run. The criteria as written tolerate it:

- section D names four apps for the recall bar (Firefox, VS Code, Git, Notepad++);
- the gate's default corpus has no 7-Zip;
- `docs/ENGINE_PLAN.md` puts 7-Zip in M1b.

The criteria that apply to every run (danger, precision, user data) pass trivially for an empty plan. It should be recorded as a known attribution gap, not counted as a pass on recall: "purge above BCU per app" is false for 7-Zip.

## Where the BCU numbers come from

They are **not from this campaign**. `m1a.sh` copies `vm/truth/frozen/<id>/plans/bcu.json` into each run, and those files are byte-identical to the r2 copies. That plan is BCU's removal list recorded on the M0 run of 2026-11-11, re-scored against r2's truth. Items with run-specific names score `gone`.

| App | Bar (frozen plan on frozen truth, `vm/truth/FROZEN.md`) | Same plan on r2 truth |
|---|---|---|
| Firefox | 20.8% | 20.0% |
| VS Code | 0% | 0% |
| Git | 0% | 0% |
| Notepad++ | 3.4% | 3.6% |

Purge clears both columns. On the frozen truth itself, the r2 Firefox plan scores 29.2% against 20.8% (`vm/truth/r2/m1a-frozen-firefox.md`), with danger 0 and precision 100% in all five frozen cross-checks.

## The 11 sanity differences

Accepting them was justified by what they are, but not by how it happened. `inbound-gate-score.sh` re-runs with `--accept-sanity-diff` on any exit 3, which removes the "investigate first" stop of gate step 9. None of the 11 makes the truth set wrong in Purge's favour beyond one item per app.

| # | Items | Class | Evidence |
|---|---|---|---|
| 6 | Two `HKLM\SOFTWARE\Classes\CLSID\{random}` keys each in vscode, git, firefox | OS noise, wrongly counted as leftover | Each key has one value, `AppID={random}`, no subkeys, written 2 to 7 s after snap0. The same pair appears in all three r2 null runs and in two of three r1 null runs, with no app involved. |
| 1 | `Control\hivelist` value `\REGISTRY\MACHINE\COMPONENTS` in vscode | OS noise, wrongly counted as leftover | Windows servicing mounted the COMPONENTS hive during that run; the same run has Component Based Servicing and 16 WOSC changes. |
| 4 | UserAssist `Count` value missing in vscode, git, firefox, npp (present in the frozen truth) | Environment | See next section. |

The sanity report lists a seventh Firefox CLSID, `{1814CEEB…}`. That is an artefact of comparing GUID-normalised counts: the key is in the frozen truth too.

Effect on the score: the seven noise items sit in the denominator as missed leftovers, so they lower recall (vscode by 3 items, git by 2, firefox by 2). Without them Firefox would be 7/23 = 30.4%.

## Did the Linux host change what Windows or the apps wrote?

One thing changed. **Explorer wrote nothing to UserAssist in any r2 run.**

- In r0 and r1 (Windows host) each launch added one value named after the app, and `UEME_CTLSESSION` changed.
- In r2 the `Count` key is untouched between snap0 and snap2 in every app run.
- The Linux smoke runs `lx0t`, `lx1t` and `lx2t` show the same. `lx0t` ran on stock VirtualBox without the 3D-off switch, so the cause is the Linux host, not KVM or 3D off specifically. I did not find the mechanism. The launch method is the same (`PurgeRigLaunch` task, medium IL) and explorer is running in both.

Consequences:

- One truth item per launched app is absent. The engine missed that item in every r1 run, so its absence raises r2 recall slightly. Firefox would be 7/26 = 26.9% with it. No criterion flips.
- UserAssist traces are not exercised by this campaign at all.

Everything else matches. After normalising random names, the r2 leftover sets equal the frozen ones except for the items above. Installer hashes and the OS build are identical to r1. 7-Zip's truth is identical to r1's. Jump lists, `JumplistData`, `AppBadgeUpdated`, Prefetch and the sparse-package registrations are all present. Differences in the recorded uninstall process lists are sampling.

## The three new noise rules

All three are legitimate. Only one has any effect on r2.

| Rule | Judgement | Effect on r2 |
|---|---|---|
| `Windows Error Reporting\TermReason` | Legitimate. Every record in every r2 and r1 snapshot I read has `Terminator=HAM`, `Reason=4`: Windows' Host Activity Manager ending background processes. Seven new PIDs appear in each app run whatever the app (7-Zip included), and the null runs have them too; they only escape the ambient set because PIDs are too short to generalise. | Removes 7 items per run (6 in vscode, 1 in vscode-user). |
| TrustedInstaller `Start` / Winlogon `Events` | Legitimate: two exact value names, changed values only. | None; no r2 item matched. |
| `SIH\SLS\{GUID}` | Legitimate: the Windows Update self-healing client's cache. | None; the null runs already cover it. |

**Firefox on honest accounting.** The purge plan covers 7 truth items with Safe or Likely offers in every variant.

| Accounting | Firefox recall_visible_nd |
|---|---|
| As scored | 7/25 = 28.0% |
| No servicing rules at all (re-scored in scratch) | 7/32 = 21.9% |
| No servicing rules, UserAssist item added back as missed | 7/33 = 21.2% |
| Frozen truth | 7/24 = 29.2% |
| Bar | 20.8% |

Firefox clears the bar without any of the rules, by one item in the worst case. The pass does not depend on the approval of 2026-11-14.

Of the 12 older servicing rules, only CBS, WOSC, PackageRepair, Defender history and Fcon fire on r2 (vscode 18, vscode-user 2, firefox-tb 2, npp 1). No recall bar depends on them.

## The GUID wildcard change

The change in `vm/rigtool/src/ambient.rs` is correct and conservative. A wildcard directly under `Classes\CLSID` would label an app's own leftover CLSID as ambient and inflate recall. Its cost is the six CLSID items above (on r2: vscode, git and firefox; not Notepad++ this time).

The decision log withholds a rule until the churn "is shown to be OS-only". On the Inbound image that is now shown: five of six null runs across r1 and r2 have the pair. A rule keyed on the shape (new CLSID key, single `AppID` value, no subkeys) would be justified. It can only raise recall, so its absence does not threaten the pass.

## Is the scoring trustworthy?

Yes, with these notes.

- **Reproducible.** Ambient set, truth items and score table are identical on re-run. The Linux scorer binary (built 2026-11-14 03:21) is newer than every file in `vm/rigtool/src`.
- **Engine identity is only indirectly recorded.** `run.json` has no engine hash. The link is the console log line (`engine 1d7524d4cd0c`) plus the file on disk, which has that hash and was last written 2026-11-14 04:23, before the campaign. The source tree hash cannot be checked any more.
- **Scorer and labels are uncommitted.** `score.rs`, `truth.rs`, `ambient.rs`, `mk_labels.py`, `m1a.sh` and `_os-servicing.json` differ from HEAD or are untracked. The only app label file with a content change is `firefox-tb.json`: kept-owner rules for the Maintenance Service that stays installed for Thunderbird (2 items in r2). That is reasonable.
- **No app-named item is hidden by the new rules.** Ambient items that name the app come from the frozen M0 `_os.json` rules (BAM records, StateRepository cache, installer Prefetch), not from anything added since.
- **The 10 runs are one campaign.** All `ok`, one version of the guest scripts, null runs spread first, middle and last. Every engine call exited 0, and `entry_gone` and `verify_gone.passed` are true.
- **`m1a-sanity.md` is mislabelled.** Its heading and column say "r0" for any prefix.

## Before the gate can be declared passed

Must fix:

1. **Put the classification of the 11 sanity differences into the gate record**, and stop `inbound-gate-score.sh` accepting a residual on its own. As run, step 9 was skipped.
2. **Compare the m1a.6 re-plan of these seven captures with the r2 plans.** This result covers m1a.5 only; any run whose plan differs needs a live rerun, per the decision of 2026-11-14.
3. **Rewrite `docs/M1A_GATE.md`** with the r2 numbers, the engine hash, the Linux host with 3D off, the fact that the BCU figures are the frozen plan re-scored, the 7-Zip gap as out of the written scope, and the missing UserAssist trace as "not exercised".
4. **The bands review must pass** (other reviewer).
5. **Commit the scorer, labels and `vm/truth/r2` together with the result**, after asking the user, so the numbers can be reproduced from git.

Nice to have:

- A noise rule for the AppID-only random CLSID pair, and one for the `hivelist` COMPONENTS value.
- Find out why UserAssist is not written under the Linux host, or record it as a rig limit in `vm/RIG.md` §9.
- Write the engine's SHA-256 into `run.json`.
- Have the babysitter quote `visible_nd`.
- Fix the hard-coded "r0" in the sanity report.
- 7-Zip attribution (M1b).

Scratch outputs of this review (re-scored r2 and r1, with and without servicing rules): `/tmp/claude-1000/-mnt-C-Users-<user>-Desktop-uninstall-purge/2a88ab4a-cd5b-4ff0-bb84-ac5184aaad71/scratchpad/gate/rev/`
