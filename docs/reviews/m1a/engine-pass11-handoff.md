# Pass eleven: engine state for handoff (2026-11-15)

Repo `/mnt/C/Users/kaank/Desktop/uninstall/purge`, branch `m1a`, everything uncommitted on top of `9d4b906`.
POLICY_VERSION is `m1a.6`.

## 1. Tree hash

- Current tree: `4f2f036d1c6d2ec2371d9941cbc6dc9c3caa8946ac32626615a53e6fd3512ae1` (235 files).
- The verification below ran on the tree before the last four edits: `43f24f9cc9cfa08f0038c3c8e5a4fdc55f70dc8b004670b2141201f1ba38d0da`.
- Command: `cd <repo> && find crates bins -type f | sort | xargs -d "\n" sha256sum | sha256sum`

**The current tree compiles but its tests have not been run.** The last four edits (listed in 2, marked "after verification") were built with
`cargo test -p purge-plan -p purge-scan` (all test binaries compiled); every binary then died at start with
`wine client error: version mismatch 971/979` (the wineserver changed under the session), and I was told to stop.
`cargo fmt --all` was run after the last edit.

## 2. Changes of this pass

Review items 1 to 8:

| # | Change | File |
|---|---|---|
| 1 | `is_one_path` refuses `; " < > | ? *` | `crates/purge-guard/src/prefix.rs` |
| 2 | `ScanCtx::run` seals a co-removed product's candidate with that product's fingerprint | `crates/purge-scan/src/framework.rs` |
| 3 | REG_BINARY/REG_NONE no longer skip the rule: numbers pass, own place passes, data over the scan limit is unproven, path-shaped UTF-16 runs must be the app's | `framework.rs` (`data_unproven`) |
| 4 | Text after the first NUL of a string value makes it unproven | `framework.rs`, `crates/purge-source/src/types.rs` (`RegData::has_text_after_nul`) |
| 5 | Name exemption: whole name is a plain own path, or holds an id of the app; never in a command place | `framework.rs` (`named_after_app`, `data_unproven`) |
| 6 | Table test goes through `run`; positive control for all 13 registry scanners; rows for 1, 3, 4, 5; co-removed case | `crates/purge-scan/tests/reg/hostile.rs` |
| 7 | Token anchors in the reference snapshot are Tier B unless the installer record covers the value | `framework.rs` (`in_ref_snapshot`) |
| 8 | Product data folder (`UserData` path, `UserData` blocker, `ProductSubfolderOfVendor`, no `GenericName`) is at least Likely; cannot be Safe (category and blocker) | `crates/purge-policy/src/band.rs`, cases in `crates/purge-policy/tests/golden.rs` |

Additions A and B:

| | Change | File |
|---|---|---|
| A | A `<Vendor>\<Product>` folder whose product name another installed app carries (all significant tokens of the folder name, vendor words aside) gets hard blocker `ReferencedByOtherApp { app }`: Blocked, "still used by" | `crates/purge-scan/src/fs_appdata.rs` (`other_app_named`, `offer`) |
| B | `Classes\Applications\<exe>` matched by bare main-exe name only: offered only if the installer record covers it, or the subtree was read in full, names no path, and the name is the product's own. A key another known app claims stays listed Blocked | `crates/purge-scan/src/reg_apppaths.rs` (`exe_key`) |
| B | A key whose every path leads to a file that outlived the uninstall unproven (`App Paths\rg.exe`) is not offered | `reg_apppaths.rs` |
| B | `OpenWithList` entry and its `MRUList` letter are skipped when `Applications\<exe>` leads elsewhere | `crates/purge-scan/src/cls_fileexts.rs`, helper `reg_apppaths::bare_name_leads_elsewhere`, `common::names_a_path` in `crates/purge-scan/src/reg_software.rs` |
| B | Any parent offered with a whole-tree action (ticked or not) gets `ContainsOtherApp` when a descendant is Blocked for another owner | `crates/purge-plan/src/collapse.rs` (`objections`, `is_offered_whole`) |

After verification (compiled only, untested):

- `collapse.rs`: `objections` never reports a blocker the parent already carries, so the repeat-until-quiet loop cannot spin.
- `reg_apppaths.rs`: `outlived()` = `verify_gone_passed() && survived_unproven()`. Without it a scan of a still-installed app dropped its own `App Paths` and `Applications` keys (see 3, live modes).
- `crates/purge-scan/tests/reg/main.rs`: pin for that (app not verified gone, keys still listed).
- `collapse.rs` test: a parent Blocked for its own reason gains nothing.

Pins: `hostile.rs` (8 tests), `reg/main.rs` (`apppaths_bare_exe_name_is_not_ownership`, `apppaths_key_of_a_file_that_outlived_the_uninstall_is_not_offered`), `assoc/main.rs` (`file_exts_entry_of_a_portable_copy_is_not_offered`), `fs_appdata.rs` (`a_product_folder_another_installed_app_is_named_after_is_kept`), `collapse.rs` (`a_child_kept_for_another_owner_blocks_an_unticked_parent_too`).

Not changed: `cls_assoc/handler.rs` `exe_named_subkeys` (`.ext\OpenWithList\<exe>` keys) still matches on the bare name.

## 3. Verified on tree 43f24f9c

- **ci-linux: PASS**, 962 passed, 10 failed (the 10 known wine failures), fmt, clippy, features, check-deps, scanner-coverage ok. Log `ci11.log`.
- **Ignored snapshot tests (msvc):** 10 passed, 0 failed. Log `ignored11.log`.
- **replay-all + score:** macro recall_listed 58.7%, precision_safe 100%, danger 0 (vscode 89.0, git 25.0, firefox 41.7, npp 79.3). Logs `replay-all11.log`, `score11.log`.
- **Table test:** 8 of 8 in `hostile.rs`, inside the suite above.
- **Mutations:** baseline clean (492 passed). 60 of 65 ran: 59 killed, 1 not killed. Log `mut11-run.log`, per-mutation logs `mut11-<name>.log`.
  - **B8b** (unticked parent also gets `UnmatchedChildren`) is printed as SURVIVED, but it hung: the `collapse` loop never ended because the parent stayed offered and was reported again every round. The coordinator killed the process. The gap was real: termination depended on that one condition. The hardening edit removes the dependency; it is untested.
  - Not run: B8c, T1, T2, T3, T4 (T1 to T4 were killed in the earlier 50-mutation run), and B4b and B8d, which were added afterwards.
  - `mut11.py` now has a 900 s timeout per mutation and reports `HUNG`; that code path has not been exercised.
- **Re-plan, 74 older captures, four modes** (binary built from touched sources in `tgt-new`, rule string checked; all 74 replayed in each mode). Against the gate tree, on and cutoff modes are identical to each other:
  - Weak to Likely, 30 rows: `%APPDATA%`/`%LOCALAPPDATA%\Mozilla\Firefox` and `%APPDATA%\Mozilla\Thunderbird`, no sibling installed.
  - Weak to Blocked, 8 rows: the same Firefox folders in x0/x1 `ff-esr` and `ff-devedition`; their two `...\Mozilla` containers (Weak) leave the plan, 8 rows.
  - Likely to Blocked, 4 rows: `HKU_Classes\vscode` in f0d/f1d-vscode-user and x0/x1-vscode-with-user.
  - Likely to gone, 16 rows: `Applications\notepad++.exe`, `.log\OpenWithList|a` and its MRU letter (4 runs), `App Paths\rg.exe` (2), `Applications\Code.exe` (2).
  - 42 Safe rows change evidence tier only (token snapshot A/8 to B/8 on `AppBadgeUpdated`, `JumplistData`).
  - No new Safe, no band up other than the 30.
  - **Live and live-cutoff modes: a regression on the verified tree.** 65 Likely rows gone, among them the app's own `App Paths\firefox.exe`, `Applications\firefox.exe`, `App Paths\notepad++.exe`, `vlc.exe`, `thunderbird.exe`: with the app still installed every file "survived". The `outlived()` edit is the fix; not re-planned. Also 610 keys Likely to Blocked `ContainsOtherApp` in runs where another VS Code or Firefox install stays; that is the new parent rule applied to unticked parents, and I did not review those rows one by one.
  - Files: `diffa-gate-{on,cut,live,livecut}.txt`, `diffa-p10-*.txt`.
- **Re-plan, new captures:** 29 covered: r2-7zip, r2-firefox, r2-firefox-tb, r2-git, r2-npp, r2-vscode, r2-vscode-user; f2d-firefox, f2d-git, f2d-npp, f2d-vlc, f2d-vscode-user; x2-ff-devedition, x2-ff-esr, x2-ff-reinstall, x2-ff-tbafter, x2-git-toolsdir, x2-git-upgrade, x2-git-userstate, x2-nb-firefox-tb, x2-npp-userfiles, x2-thunderbird, x2-vlc, x2-vscode-insiders-pair, x2-vscode-upgrade, x2-vscode-userstate, x2-vscode-with-user, x2-vscode-zipcopy, x2-winmerge. Skipped: r2-null1/2/3, f2d-null1, f2d-null2 (no fingerprint or plan), x2-nb-vscode (no run.json).
  - Offline replay does not reproduce the VM plans exactly (`diffb-vm-gate.txt`: gate tree replayed against the VM's own plans already differs, mostly `DanglingRef` missing offline). So the engine change is read from gate-tree replay against new-tree replay, `diffb-gate-new.txt`; `diffb-vm-new.txt` has the full per-run lists against the m1a.5 plans.
  - Profile rows, before to after:

    | Run | `Roaming\Mozilla\Firefox` | `Local\Mozilla\Firefox` |
    |---|---|---|
    | r2-firefox, r2-firefox-tb, f2d-firefox, x2-ff-tbafter, x2-ff-reinstall, x2-nb-firefox-tb | Weak to Likely | Weak to Likely |
    | x2-ff-esr | Weak to Blocked (Mozilla Firefox ESR) | Weak to Blocked |
    | x2-ff-devedition | Weak to Blocked (Firefox Developer Edition) | Weak to Blocked |
    | x2-thunderbird | `Roaming\Mozilla\Thunderbird` Weak to Likely | n/a |

    None preselected. In ff-esr and ff-devedition the `...\Mozilla` containers (Weak) leave the plan.
  - Part B rows gone: x2-npp-userfiles `Applications\notepad++.exe`, `.log\OpenWithList|a`, MRU letter; x2-git-toolsdir `App Paths\rg.exe`; x2-vscode-userstate `Applications\Code.exe`. Likely to Blocked: `HKU_Classes\vscode` in x2-vscode-with-user and f2d-vscode-user.
  - `Applications\updater.exe` (x2-ff-devedition) is not in the capture, so neither tree reproduces it offline; only the unit pin covers it.
  - r2 runs lose no row; their only differences are the profile rows and the token evidence tier.
  - This preview result for the 29 is from the final script's run on tree 43f24f9c (`diffb-gate-new.txt` totals: 13 Weak to Likely, 4 Weak to Blocked, 2 Likely to Blocked, 5 Likely gone, 4 Weak gone, 19 evidence-only).
- **`HKLM\SOFTWARE\Mozilla\MaintenanceService`:** still Likely after fix 2 (score 4: `ProductSubfolderOfVendor` B/3 + `TimeWindow` C/1, no Tier A). Recorded deviation, no special case added.

## 4. Not verified

- Anything on the current tree 4f2f036d beyond compiling `purge-plan` and `purge-scan` with their tests. `purge-engine` and `xtask` were not rebuilt after the last four edits.
- The live-mode fix and the collapse hardening (no test run, no re-plan).
- Mutations B4b, B8b (after hardening), B8c, B8d, T1 to T4 on the final tree.
- The 610 live-mode Likely to Blocked rows, row by row.
- Goldens were blessed before the last four edits; those edits should not change them, unchecked.

## 5. Commands

Linux (wine must be restarted first: `wineserver -k`, then check `wine --version` matches the server):

```
source ~/purge-target/env-win.sh; export CARGO_BUILD_JOBS=8 RUST_TEST_THREADS=8
cd /mnt/C/Users/kaank/Desktop/uninstall/purge
# everything in one go (ci, ignored tests, replay-all + score, re-plans, mutations, hash at start and end):
~/purge-target/pass11/final11.sh > ~/purge-target/pass11/final11.log 2>&1
# or singly:
~/purge-target/ci-linux.sh
CARGO_TARGET_DIR=~/purge-target/gnullvm cargo test --workspace --target x86_64-pc-windows-gnullvm --no-fail-fast -- --test-threads=8
CARGO_TARGET_DIR=~/purge-target/gnullvm cargo test -p purge-plan -p purge-scan --target x86_64-pc-windows-gnullvm -- --test-threads=8
PURGE_RUNS_DIR=$HOME/purge-target/runs-m0 CARGO_TARGET_DIR=$HOME/purge-target/ci-linux cargo xwin test --workspace --target x86_64-pc-windows-msvc --no-fail-fast -- --ignored
CARGO_TARGET_DIR=~/purge-target/gnullvm cargo run --release -q --target x86_64-pc-windows-gnullvm -p xtask -- replay-all --runs ~/purge-target/runs-m0 --no-score
~/purge-target/rigtool-linux/release/rigtool score --set ~/purge-target/runs-m0/{vscode,git,firefox,npp}
cd ~/purge-target/pass11 && python3 mut11.py                    # all 67; or: python3 mut11.py B4b-present-file-of-an-installed-app B8b-unticked-parent-gets-unmatched B8c-blocked-parent-checked-again B8d-objection-reported-twice
python3 cmp4.py b-gate b-new        # after final11.sh rebuilt b-new; a-new/<mode> against ~/purge-target/pass10/after9b/<mode>
```

Windows: `cargo xtask ci` covers fmt, clippy, features, tests, check-deps and scanner-coverage; the ignored snapshot tests are `cargo test --workspace -- --ignored` with `PURGE_RUNS_DIR` set to the runs folder; `cargo xtask replay-all --runs <runs> --no-score` then `rigtool score --set ...`. The re-plan comparison and `mut11.py` are Linux scripts (wine paths) and have no Windows form.

## 6. Item 10 (ran on the gate tree copy)

- `"<app>\x.exe" /args` outside command places (`/setup` in a foreign key, `-multiInst` in Environment): already **Likely** on the gate tree. `"<exe>"` alone was Safe.
- `rundll32.exe "<app>\x.dll",Start` and `cmd.exe /c start "" "<exe>"` in Run: **Safe and ticked on the gate tree** through REG-RUN (the REF-ANY copy was Likely). Pass ten made them Likely by design.

## Scratch

`/home/kaan/purge-target/pass11`: `final11.sh`, `final11.log`, `ci11.log`, `ignored11.log`, `score11.log`, `mut11.py`, `mut11-run.log`, `diffa-*.txt`, `diffb-*.txt`, `newruns.txt`, `vmplans/`, `b-gate/`, `b-new/`, `a-new/`, `ws/` and `xtask-new.exe` (built from tree 43f24f9c, stale against the current tree).
