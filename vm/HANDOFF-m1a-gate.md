# Handoff: M1a gate, state at 2026-11-15 ~07:30 (Linux host to Windows)

Written when the user paused the Linux session to move to Windows. Everything is committed on branch `m1a` and
pushed. Decisions taken along the way are in `docs/DECISIONS.md`; review reports are in `docs/reviews/m1a/`.

## One-paragraph state

The M1a gate campaign passed on the **m1a.5** engine (clean base: both reviews pass; dirty base, extended set and
no-baseline set: nothing dangerous ticked after the scorer fixes). The engine source has since moved to **m1a.6**
with fixes the reviews asked for. **The m1a.6 tree compiles but is not fully verified, and one known regression
fix in it is untested.** The gate is not declared passed until the m1a.6 engine is verified and the captures are
re-planned with it. `docs/M1A_GATE.md` still says FAIL from the first gate and has not been rewritten.

## Engine

| Tree | Hash (crates+bins) | Policy | Status |
|---|---|---|---|
| Gate tree | `90727292…` | m1a.5 | What the VM campaigns ran. Binary sha256 `1d7524d4cd0c…`. |
| Pass ten | `24226d69…` | m1a.6 | Central "value content is wholly the app's" rule. Fully verified, reviewed: accept with required changes. |
| Pass eleven, verified | `43f24f9c…` | m1a.6 | Review fixes 1 to 8 plus additions A and B. CI, table test, replay, 59 of 60 mutations. **Has a live-mode regression** (below). |
| **Committed tree** | `4f2f036d…` | m1a.6 | Pass eleven plus four small edits that fix the regression and a non-termination risk. **Compiles; no test, re-plan or mutation has run on it.** |

Hash command: `find crates bins -type f | sort | xargs -d "\n" sha256sum | sha256sum` (Git Bash on Windows; line
endings must be as committed).

Full engine detail, per change and per file: `docs/reviews/m1a/engine-pass11-handoff.md`. Diffs of the re-plans:
`docs/reviews/m1a/pass11/`. The pass-ten review: `docs/reviews/m1a/engine-pass10-review.md`.

**Open on the engine, in order:**

1. Run the full suite on the committed tree (`cargo xtask ci` on Windows; all tests pass there, the 10 wine-only
   failures do not exist on Windows). Then the ignored snapshot tests with `PURGE_RUNS_DIR` set.
2. **Live-mode regression** (on `43f24f9c`): with the app still installed, 65 Likely rows vanished, among them the
   app's own `App Paths\firefox.exe` and `Applications\<exe>`, because every file counted as "survived the
   uninstall". The fix (`outlived()` in `crates/purge-scan/src/reg_apppaths.rs`: the surviving-file rule applies
   only when verify-gone passed) is in the committed tree, untested. Re-plan the 74 older captures in live and
   live-cutoff modes and confirm those rows are back.
3. **Collapse non-termination**: under mutation B8b the `collapse` loop in `crates/purge-plan/src/collapse.rs`
   never ended. The hardening (`objections` never reports a blocker the parent already carries) is in the
   committed tree, untested. Rerun mutations B4b, B8b, B8c, B8d, T1 to T4.
4. 610 keys go Likely to Blocked (`ContainsOtherApp`) in live modes where another VS Code or Firefox install
   stays. Nobody has looked at those rows one by one. Decide whether that is right or too broad.
5. One more independent review of pass eleven (critical routing: Fable, medium effort).
6. Build the msvc binary from the final tree, install it as `target/release/purge-engine.exe`, and re-plan the new
   captures (`vm/runs/r2-*`, `f2d-*`, `x2-*`, `x2-nb-*`; these folders are gitignored and exist only on this
   disk). Expected differences against the m1a.5 plans are listed in the engine handoff, section 3. Rows that
   moved on purpose: Firefox and Thunderbird profile folders Weak to Likely (Blocked when a sibling is installed);
   the bare-exe-name rows gone; `HKU_Classes\vscode` Likely to Blocked. Then one short live campaign on the
   Firefox runs with the final binary.

## VM campaigns (all on the m1a.5 binary)

| Campaign | VM, snapshot | Runs | Result |
|---|---|---|---|
| `r2-` gate | Inbound, rig-base | 7 apps + 3 nulls | Score review: pass. Bands review: pass with notes. |
| `f2d-` dirty | Inbound, dirty-base | 5 apps + 2 nulls | 7 "danger" items, none ticked: 4 Blocked/kept, 3 shortcut-history slots. No engine fault. |
| `x2-` extended | Clean-Pro, rig-base | 16 | Nothing dangerous ticked after scorer fixes. 7 foreign items Likely and unticked: fixed in m1a.6 (addition B). |
| `x2-nb-` no baseline | Clean-Pro, rig-base | 5 | 2 items, both the shortcut-history slot, unticked. |

Scores are in `vm/truth/{r2,f2d,x2,x2-nb}`. Clean-base recall (visible, the gate column): VS Code 88.4%, VS Code
user 88.3%, Git 23.5%, Firefox 28.0%, Firefox with Thunderbird 31.6%, Notepad++ 82.1%. Firefox clears its 20.8%
bar with or without the three servicing noise rules.

Scorer and truth changes made after the campaigns (all re-scored): `vm/rigtool/src/score.rs` (danger split into
offered / kept / blocking; replaced-value class; an earlier install of the same app in snap 0), `truth.rs` (Store
self-update), `vm/truth/m1a.sh` (sanity acceptance needs `vm/truth/r2/m1a-sanity-classified.json`; `M1A_SANITY=skip`
off rig-base), `mk_labels.py` and labels. Not done: Store registry churn (about 550 rows per Clean-Pro run still
inflate denominators), `vm/RIG.md` not updated for these, null runs inside the extended campaign.

## Still to do before M1a closes

- Engine items 1 to 6 above.
- Rewrite `docs/M1A_GATE.md` (verdict, the sanity classification, the waivers and deviations from
  `docs/DECISIONS.md`, the 12 deferred limitations from the pass-seven review).
- Update `vm/RIG.md` for the scorer changes.

## After M1a

- **M2 executor** is next (design `docs/M2_DESIGN.json`, 27 packages, 9 waves). Start with M2-S0 (scaffolding),
  then wave 1. On Linux the wave workflow is `tools/linux/workflows/m2-wave-linux.js`; on Windows use the original
  wave workflow. Uncommitted-before, now committed: `install/`, `vm/guest/m2-*.ps1`, `vm/truth/m2-traps.json`.
  The M2 VM gate needs an `m2-base` snapshot and a D: disk in the VM.
- **UI shell** exists already: commit `973a791` on local branch `claude/ui-shell-7a9c31` (WinUI 3, sample data),
  not pushed. M3 builds on it. WinUI cannot be built on Linux.
- M1b, M3 to M7 have no design files yet.

## Host notes

- **Windows:** run `chkdsk C: /f` first; the Linux side logged NTFS index errors on C: on 2026-11-14.
  `target/release/purge-engine.exe` and `vm/rigtool/target/release/rigtool.exe` are the **m1a.5 gate binaries built
  on Linux** (cargo-xwin, LLD); the original Windows builds sit beside them as `.bak-20261114-*`. A Windows
  `cargo build --release` will replace them, which is what you want once the engine is verified.
- Both rig VMs are powered off. Inbound's current snapshot is `dirty-base`, Clean-Pro's is `rig-base`. The Linux
  side changed NVRAM snapshot paths in the `.vbox` files from `\` to `/`; originals are in each VM folder under
  `_vbox-backup-20261114/`. If VirtualBox on Windows complains about the VMs, restore those.
- The VM password file is outside the repo and is never committed.
- **Linux:** scripts are in `tools/linux/` (copies of `~/purge-target/*`): `ci-linux.sh` replaces `cargo xtask ci`,
  `build-msvc.sh` builds the msvc binaries, `campaigns/*.sh` run and score the four campaigns. Restart wine
  (`wineserver -k`) before testing: it broke with `version mismatch 971/979` at the end of the session. Keep
  builds at `CARGO_BUILD_JOBS=8` while VMs run; an earlier session was killed for lack of memory.
- Model routing for agents: engine code and its reviews on the strongest model at medium effort; rig and UI on
  Opus medium; campaign babysitting on Haiku.

## History

The earlier text of this file (first gate, 2026-11-13, engine m1a.3) is superseded. The first gate failed on
shared Mozilla items offered with Thunderbird installed; those are no longer offered.
