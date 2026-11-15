# Handoff: M1a gate, state at 2026-11-15 (Windows host)

Decisions taken along the way are in `docs/DECISIONS.md`; review reports are in `docs/reviews/m1a/`; the gate
report is `docs/M1A_GATE.md`.

## One-paragraph state

**The M1a gate is declared passed** (`docs/M1A_GATE.md`, verdict PASS with two recorded deviations). The engine
is at policy **m1a.6** and verified: full CI, snapshot tests, an independent review of pass eleven with a
follow-up ("accept"), a mutation run, an offline re-plan of every capture, and a short live campaign with the
final binary. The work is committed locally on `m1a` on top of `f0923b2`; **nothing of it is pushed.** One
point is a judgement the user may want to look at: the live repeat of the two Firefox gate runs was done on
Clean-Pro, because the Inbound VM could not be loaded on Windows at the time. The VM was repaired afterwards
(below) and the repeat was run on Inbound too (`r3i-`): same result, so that judgement is closed.

## Engine

| Tree | Hash | Policy | Status |
|---|---|---|---|
| Gate tree | `90727292…` (raw bytes) | m1a.5 | What the four VM campaigns ran. Binary sha256 `1d7524d4cd0c…`, kept as `target/release/purge-engine.exe.bak-m1a5-gate-20261115`. |
| Committed at `f0923b2` | `4f2f036d…` (raw bytes), `abadd0a2…` (git content) | m1a.6 | Pass eleven as handed over from Linux. |
| **Commit `622c64d`** | `8fcaab30…` (git content) | m1a.6 | Review fixes. `target/release/purge-engine.exe` (sha256 `128556f84e2b…`, Windows msvc build) is built from it; the live check ran this binary. |
| Later commits | | m1a.6 | Tests and documents only; no engine source change. |

Hash command: `python -I docs/reviews/m1a/pass11/treehash.py . [<commit>]`. It hashes what git stores, so line
endings of the checkout do not matter. The older hashes in the table and in the reviews are over the raw bytes
of the Linux working tree and compare only with each other (`docs/DECISIONS.md`, 2026-11-15).

What was done on the six open engine items of the previous handoff:

1. **Suite.** `cargo xtask ci` passes on the final tree (all steps; 981 tests at `622c64d`, more after the
   added tests). The 10 ignored snapshot tests pass with `PURGE_RUNS_DIR=vm\runs`. The one failure met on the
   first run was a slip in a test, fixed in the test.
2. **Live-mode regression: fixed.** Of the 65 lost Likely rows 51 are back; the 14 that stay away are the
   intended bare-name rows. `outlived()` now rests on "verify-gone passed, or the main exes are gone and at
   least one is known".
3. **Collapse loop.** B8b no longer hangs; B8d survived and got a test. Full mutation run on Windows: 86 of 90
   killed; the 4 survivors were unpinned review fixes and got tests. Those 4, the 7 whose code changed
   afterwards and 5 new ones were rerun on the final tree: 16 of 16 killed (end of
   `docs/reviews/m1a/engine-pass11-review.md`).
4. **The 610 Likely to Blocked rows: right**, kept. Each has a child already Blocked for the sibling install.
5. **Independent review:** `docs/reviews/m1a/engine-pass11-review.md`. First verdict "accept with required
   changes" (three constructed inputs reached Safe); all required changes made; follow-up verdict "accept";
   its three remaining points fixed as well. No real capture changes in any of 177 re-plans.
6. **Final binary, re-plan, live check.** Built on Windows. Offline re-plan of the 29 campaign captures shows
   only the intended differences against m1a.5. Live campaign `r3-` on Clean-Pro (firefox, firefox-tb, ff-esr,
   extra checks): all runs ok, plans as predicted, nothing dangerous offered, scores in `vm/truth/r3`.

Left open on purpose (all in `docs/DECISIONS.md`):

- **M2 executor requirement:** a ticked whole-tree parent with a Blocked item below it is refused, or the
  Blocked item is spared (review finding 6).
- Case folding follows Windows only in the central fold functions; about 150 direct `to_lowercase()` calls are
  untouched (M1b).
- Known limits of the content rule: relative commands in `names_a_path`, 8-bit relative paths in binary data,
  `Winlogon` / `Active Setup` / `Image File Execution Options` are not start places, no test for the
  vendor-word filter of `other_app_named`.
- `x1-git-toolsdir` and `x2-git-toolsdir`: the Windows replay lists three Likely rows fewer than the Linux
  harness did (cautious side, cause not found).
- The "12 deferred limitations from the pass-seven review" named by the previous handoff are not in the
  repository; if that review still exists in the Linux scratch space, copy it to `docs/reviews/m1a/`.

## Tools added on Windows

- `cargo xtask replay --run <dir> --app <id> -o <plan> [--live] [--fp <fp.json>] [--overlay <fixture>]`: plans one
  capture offline and writes the scan sidecar next to the plan. `--live` scans the still-installed app.
- `docs/reviews/m1a/pass11/mutwin.py`: the mutation table of `mut11.py` brought up to the current source, plus
  V1 to V28 for the review fixes. `python -I mutwin.py <repo> <scratch dir> [names…]`; about 3.5 minutes per
  mutation, safe to run in several scratch directories at once.
- `docs/reviews/m1a/pass11/treehash.py`.
- The re-plan comparison scripts (offline harvest with the run's Inno log laid over the fixture, diff of
  sidecars) are session scratch and were not kept; `docs/DECISIONS.md` describes the method.

## VM campaigns

| Campaign | Engine | VM, snapshot | Runs | Result |
|---|---|---|---|---|
| `r2-` gate | m1a.5 | Inbound, rig-base | 7 apps + 3 nulls | Score review: pass. Bands review: pass with notes. |
| `f2d-` dirty | m1a.5 | Inbound, dirty-base | 5 apps + 2 nulls | 7 "danger" items, none ticked, no engine fault. |
| `x2-` extended | m1a.5 | Clean-Pro, rig-base | 16 | Nothing dangerous ticked; 7 foreign items Likely, fixed in m1a.6. |
| `x2-nb-` no baseline | m1a.5 | Clean-Pro, rig-base | 5 | 2 items, both the shortcut-history slot, unticked. |
| `r3-` live check | m1a.6 | Clean-Pro, rig-base | 3 | Danger offered 0; ff-esr keeps 7 items Blocked; live scan 0 Safe; repeat scan identical. |
| `r3i-` live check | m1a.6 | Inbound, rig-base | 2 | Plans equal r2 except the two profile rows; danger 0; live scan 0 Safe; repeat scan identical. |

Scores: `vm/truth/{r2,f2d,x2,x2-nb,r3,r3i}`. `vm/runs/` (the captures) is gitignored and exists only on this disk.
`vm/RIG.md` now describes the scorer changes (danger split, replaced values, earlier install of the same app,
Store self-updates, classified sanity residual, scoring on Windows).

## After M1a

- **Ask the user** before pushing `m1a` or merging it.
- **M2 executor** is next (design `docs/M2_DESIGN.json`, 27 packages, 9 waves). Start with M2-S0 (scaffolding),
  then wave 1. The M2 VM gate needs an `m2-base` snapshot and a D: disk in the VM.
- **UI shell**: commit `973a791` on local branch `claude/ui-shell-7a9c31` (WinUI 3, sample data), not pushed.
- M1b, M3 to M7 have no design files yet. Items deferred to M1b are in `docs/M1A_GATE.md` section 6.

## Host notes

- **Windows, for the user:** run `chkdsk C: /f` (needs elevation and a restart); the Linux side logged NTFS
  index errors on C: on 2026-11-14. Not done by the assistant.
- **Inbound-Win11-Test works on Windows again** (repaired 2026-11-15, after the live check). It was
  `<inaccessible>` because each host keeps the VM's disk tree in its own global `VirtualBox.xml` and the Linux
  session had made a new current-state disk. The tree was written into the `.vbox`; the VM loads, has its four
  snapshots, boots from `rig-base` to the `tester` logon, and is powered off at `rig-base`. The pre-repair
  `.vbox` is `Inbound-Win11-Test.vbox.before-mediaregistry-20261115` in the VM folder.
  **On Linux the VM will now be inaccessible for the same reason**; run `vm/fix-vbox-media.ps1` there
  (`vm/RIG.md`, Linux host section). The script has only been run on Windows.
- Purge-CleanPro works on Windows, is powered off, current snapshot `rig-base`.
- The VM password file is outside the repo and is never committed.
- `target/release/purge-engine.exe` and `vm/rigtool/target/release/rigtool.exe` are now Windows msvc builds of
  the final tree; the Linux-built gate binaries sit beside them (`.bak-m1a5-gate-20261115`,
  `.bak-gate-20261115`).
- **Linux:** scripts are in `tools/linux/`. The campaign scripts there refuse an engine that does not contain
  `m1a.5`; change that check before reusing them. Restart wine (`wineserver -k`) before testing. Keep builds at
  `CARGO_BUILD_JOBS=8` while VMs run.
- Model routing for agents: engine code and its reviews on the strongest model at medium effort; rig and UI on
  Opus medium; campaign babysitting on Haiku.

## History

The earlier texts of this file (first gate 2026-11-13 on m1a.3; Linux to Windows handoff 2026-11-15 with six
open engine items) are superseded by this one.
