# M1a offline replay score (2026-11-12)

This is a **development signal, not the M1a gate**. Replay runs the engine over the frozen M0 snapshots
(`vm/runs/<app>/snap-*-{1,2}.tsv.gz`, `lists-*-1.json`, `run.json`) with no overlay. It has no file
contents, version info or signers, no Inno `unins*.dat` log (0 Inno records for all four apps), and no
shortcut targets. About 30k values with REG_BINARY-like data are unknown and 196 previews are cut at 1024
characters. Anything that depends on those inputs is under-reported here.

## How it was produced

```
cargo xtask replay-all --no-score            # writes vm/runs/<id>/plans/purge-replay.json (about 2 min)
cd vm/rigtool && cargo build --release
# per app, from vm/:
rigtool score --plan runs/<id>/plans/purge-replay.json --plan runs/<id>/plans/bcu.json \
  --truth runs/<id>/truth.json --s0 runs/<id>/snap-<id>-0.tsv.gz --s2 runs/<id>/snap-<id>-2.tsv.gz \
  --deny truth/deny.json --sid <run.json user_sid> --json ... --md ...
```

Replay is deterministic: re-running `cargo xtask replay` for firefox and vscode produced byte-identical plans.
verify-gone passed for all four runs. The BCU numbers equal the frozen `vm/truth/m0-score.md`.

`<SID>` below is `S-1-5-21-1336749127-99101324-1432799918-1000` (the rig user).

## Scores

`*_nd` recall (coverage from non-danger items only) equals the plain recall everywhere, because there are no
danger items.

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | precision_safe | danger listed / presel | userdata_presel | outcomes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| vscode | **purge** | 138 | 154 | **88.3%** | 88.3% | **87.7%** | **100% (137/137)** | 0 / 0 | 0 | hit 138 |
| vscode | bcu | 202 | 154 | 0.0% | 0.0% | 0.0% | n/a (all gone) | 0 / 0 | 0 | gone 202 |
| git | **purge** | 5 | 16 | **6.2%** | 6.2% | **0.0%** | **75% (3/4)** | 0 / 0 | 0 | hit 4, ambient 1 |
| git | bcu | 14 | 16 | 0.0% | 0.0% | 0.0% | n/a (all gone) | 0 / 0 | 0 | gone 14 |
| firefox | **purge** | 17 | 24 | **33.3%** | 20.8% | **16.7%** | **100% (10/10)** | 0 / 0 | 0 | hit 17 |
| firefox | bcu | 17 | 24 | 20.8% | 20.8% | 20.8% | 100% (9/9) | 0 / 0 | **1** | hit 9, gone 8 |
| npp | **purge** | 3 | 29 | **79.3%** | 79.3% | **0.0%** | **0% (0/1)** | 0 / 0 | 0 | hit 2, ambient 1 |
| npp | bcu | 10 | 29 | 3.4% | 3.4% | 3.4% | 100% (1/1) | 0 / 0 | 0 | hit 1, gone 9 |
| **macro** | **purge** | | | **51.8%** | 48.7% | **26.1%** | **68.8%** | 0 / 0 | 0 | |
| **macro** | bcu | | | 6.1% | 6.1% | 6.1% | 100% (2 apps) | 0 / 0 | 1 | |

**Purge compared with BCU (recall_listed):** vscode 88.3 vs 0.0, git 6.2 vs 0.0, firefox 33.3 vs 20.8, npp 79.3
vs 3.4. Purge is ahead on all four apps. This comparison is weak. The BCU plans are "removed" lists recorded
on another run, so 233 of its 243 items are `gone` (the vendor uninstaller had already removed them). Firefox
recall_safe is the one place where BCU is ahead: 20.8% for BCU vs 16.7% for Purge. BCU preselects whole keys
where Purge offers Safe values that score only as partial.

Per-kind recall_listed for Purge: vscode Path 0/13, RegKey 136/139, RegValue 0/2. git Path 0/8, RegKey 1/2,
RegValue 0/6. firefox Path 2/7, RegKey 3/10, RegValue 3/7. npp Path 5/10, RegKey 16/16, RegValue 2/3. npp
coverage comes almost entirely from the `AppxPackage` offer, which covers 25 truth items.

## Danger items

None for Purge in any app (danger_listed 0, danger_preselected 0, userdata_preselected 0).

## Purge offers that are not hits (false positives for precision)

Both are Safe and preselected, from scanner REF-ANY, with `RegMultiSzSegment` targets. Both score as `ambient`.

1. git: `RegMultiSzSegment HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\UFH\SHC | 0 | segment "C:\Program Files\Git\git-bash.exe"`
2. npp: `RegMultiSzSegment HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\UFH\SHC | 0 | segment "C:\Program Files\Notepad++\notepad++.exe"`

Why they score as ambient: `UFH\SHC` value `0` existed in snap-0 holding another app's entry (Inbound Download
Manager). The install overwrote the whole value, so truth has a `RegValueChanged` that the null runs also
produce, and it is labelled ambient. This is not a rigtool bug, and the offer is also questionable as an engine
behaviour. An SHC value is a record of the form `<.lnk>\0<exe>\0<args>`. Removing only the exe segment leaves a
malformed record holding the `.lnk` path and the arguments. UFH/SHC is shell usage history, so it belongs with
REG-PRIVACY (M1b) rather than with a value-segment edit by REF-ANY. Suggestion: treat the whole SHC value as one
unit, or leave UFH\SHC to REG-PRIVACY.

All other Purge offers are hits. For reference, these offers are hits but only `partial`, so they earn no
coverage:
- git: Safe segments of `UFH\SHC|1` (git-cmd.exe) and `UFH\SHC|2` (git-gui.exe). In truth these values are
  new, whole-value leftovers. Safe `HKLM\SOFTWARE\Classes\sh_auto_file\shell\open`, whose truth key
  `sh_auto_file` is offered only as Likely.
- firefox: Safe default values under `CLSID\{1814CEEB-…}\InProcServer32` and
  `Interface\{0D68D6D0-…,1814CEEB-…,4E747BE5-…}\ProxyStubClsid32`. Their truth items are the keys.
  Safe `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` (truth: `…\WOW6432Node\Mozilla`). Weak
  `AppData\{Local,Roaming}\Mozilla\Firefox`, and Likely `ProgramData\Mozilla-1de4eec8-…\updates\308046B0AF4A39CB`.

## Missed truth items

### Out of M1a scope (scanner or evidence belongs to a later milestone, or is out of the engine's reach)

**vscode (17 of 18)**
- FS-PREFETCH (M4): `C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf`, `-A5B0DA72.pf`, `-A5B0DA73.pf`, `-A5B0DA7C.pf`, `-A5B0DA7F.pf`
- FS-TEMP (M4): `C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp`, `…\Temp\vscode-inno-updater-1794413062.log`, `…\Temp\vscode-stable-system-x64`
- FS-JUMPLISTS (v2): `C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms`
- FS-DOTFILES (M4): `C:\Users\tester\.copilot`, `C:\Users\tester\.vscode` [user_data], `C:\Users\tester\.vscode-shared`
- REG-PRIVACY UserAssist (M1b): `V:HKU\<SID>\…\Explorer\UserAssist\{CEBFF5CD-…}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr`
- REG-PRIVACY JumplistData (M4): `V:HKU\<SID>\…\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode`
- SYS-APPX package state (M1b): `K:HKU\<SID>\…\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe`, `K:HKU\<SID>_Classes\Local Settings\…\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe`
- Beyond M1a evidence (under `Software\Microsoft`, which needs InstallerManifest/Traced; written by the app at run time): `K:HKU\<SID>\Software\Microsoft\DeveloperTools`

**git (12 of 15)**
- FS-TEMP (M4): `C:\Users\tester\AppData\Local\Temp\is-TU8SYANY8F-uninstall.tmp`
- FS-JUMPLISTS (v2): `…\Recent\AutomaticDestinations\600c39005ac9a5cc…`, `…\b9413fda1ddca9c1…`, `…\bbab4f0ce657b5d0.automaticDestinations-ms`
- FS-PREFETCH (M4): `BASH.EXE-E0DADEC9.pf`, `CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf`, `GIT.EXE-65A5E465.pf`, `MINTTY.EXE-3A9BD6BC.pf`
- REG-PRIVACY UserAssist (M1b): `V:…\UserAssist\{CEBFF5CD-…}\Count|TvgSbeJvaqbjf.Onfu`
- REG-PRIVACY JumplistData (M4): `V:…\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}`, `|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}`, `|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe`. The last one is a known-folder path (`{6D809377…}` = ProgramFilesX64) that a REF-ANY known-folder expansion could match. This is an improvement idea, not a bug.

**firefox (11 of 16)**
- FS-TEMP (M4): `C:\Users\tester\AppData\Local\Temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip`, `…\Temp\~nsuA.tmp`
- FS-PREFETCH (M4): `CRASHHELPER.EXE-C6FC1224.pf`, `FIREFOX.EXE-25FC0A66.pf`
- REG-PRIVACY UserAssist (M1b): `V:…\UserAssist\{CEBFF5CD-…}\Count|308046O0NS4N39PO`
- COM-CLASS / COM-INTERFACE (M1b), currently partial through REF-ANY values: `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}`, `K:…\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}`, `K:…\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}`, `K:…\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}`
- REG-EXEKEYED / structural (M4): `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false`
- Beyond evidence (the data `shtmlfile` / `text/html` is not a Firefox ProgID or path, so it is not in P): `V:HKLM\SOFTWARE\Classes\.shtml|` (default), `V:HKLM\SOFTWARE\Classes\.shtml|Content Type`

**npp (6 of 6)**
- SYS-APPX (M1b): `C:\ProgramData\Microsoft\Windows\AppRepository\fb764295-5706-4eaf-8f28-603f30273874_<SID>_1.rslc`
- FS-TEMP (M4): `C:\Users\tester\AppData\Local\Temp\tem5A6A.tmp`, `…\Temp\~nsu1.tmp`
- FS-PREFETCH (M4): `GUP.EXE-7F7956CE.pf`, `NOTEPAD++.EXE-0C41AC7A.pf`
- REG-PRIVACY UserAssist (M1b): `V:…\UserAssist\{CEBFF5CD-…}\Count|{6Q809377-…}\Abgrcnq++\abgrcnq++.rkr`

### In M1a scope, looks like a bug or gap (worth checking; some may be replay limits)

1. **vscode `C:\Users\tester\AppData\Roaming\Code` [user_data] is not listed.** FS-APPDATA produced 0
   candidates. `Code` is the main exe stem (`Code.exe`) and the folder should be listed as UserData (Weak, not
   preselected). This may be a replay limit, since replay has no file contents to reference the install root.
   It may also be the generic-token rule rejecting `code`. Check which one applies.
2. **git `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` is missed.** This is CLS-VERBS with the parent
   `shell` through ProvenOwnedSkeleton (M1a). The baseline is loaded in replay, so this should be reachable
   without the Inno log.
3. **git `V:…\UFH\SHC|1` and `V:…\UFH\SHC|2` are offered as segments, so they score only as partial.** Both values
   are new and every segment belongs to Git. Offering whole values (or leaving them to REG-PRIVACY) would cover
   them, and the SHC|0 false positive above has the same cause. Related: git recall_safe is 0% because
   `sh_auto_file` is offered as Likely while only its `shell\open` child is Safe (partial).
4. **firefox `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` is covered only partially.** Its only subkey,
   `Mozilla\Firefox`, is offered Safe, so the vendor key is empty after the plan. A vendor-parent rule on the
   REG-SOFTWARE side would cover it. In `HKLM\SOFTWARE\Mozilla` the vendor key is correctly kept, because it
   holds the pre-existing Defender NativeMessagingHosts.
5. **firefox `C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` is covered only partially.** Only
   `updates\308046B0AF4A39CB` is offered (Likely). The whole tree is empty after the plan.
6. **firefox `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` is missed.** Replay reports "1 co-removed of 1
   candidate" (the Mozilla Maintenance Service), but the co-removed product's leftover key is not scanned
   or offered.
7. **firefox `K:HKLM\SOFTWARE\mozilla.org` is missed.** It holds `Mozilla\CurrentVersion=160.0` and is a
   REG-SOFTWARE vendor-token variant (`mozilla.org`) of the harvested vendor `Mozilla`.

## Reading against the M1a gate (informational only)

- danger 0 and userdata_preselected 0: met in replay.
- precision_safe 100%: met for vscode and firefox. Not met for git (75%) or npp (0%). Both failures come from
  the single UFH\SHC|0 segment offer.
- Better recall than BCU on the same runs: met on recall_listed for all four apps. The BCU baseline is mostly
  `gone`, so this comparison carries little weight.
- recall_safe is low for git, npp and firefox. It depends on evidence that replay does not have (Inno log for
  git; tier-A key evidence for npp's NSIS install) and on M1b scanners (COM). The VM dry run is the real
  measurement.

## After fixes (2026-11-12)

Re-run after the five M1a replay fixes (A REF-ANY records, B CLS-VERBS/skeleton, C FS-VENDORPARENT, D
co-products and vendor variants, E FS-APPDATA main-exe name). No engine code was changed for this run.
Plans regenerated with `cargo xtask replay-all --no-score` (vm/runs/<id>/plans/purge-replay.json) and scored
with rigtool exactly as in "How it was produced" (purge-replay.json + bcu.json, s0/s2, `truth/deny.json`,
`--sid <SID>`). The BCU rows are unchanged from the table above. verify-gone passed for all four runs.

**`cargo xtask ci`: FAILED** at `cargo test --workspace`. fmt and clippy `-D warnings` pass; `check-deps`,
`ui-strings` (skipped, PURGE_UT_STRINGS not set) and `scanner-coverage` (19 scanners, 52 roots) pass when run
on their own. `cargo test --workspace --no-fail-fast` has exactly three failures, all stale test expectations
that the fixers flagged for the owners of those files, not engine regressions:

1. `purge-engine --test engine` `nsis::nsis_app_with_a_co_product_through_the_pipeline`: golden
   `bins/purge-engine/tests/golden/nsis.plan.json` lacks the new `HKLM\SOFTWARE\Fennec\MaintenanceService`
   item (fix D). Needs re-bless with `PURGE_BLESS=1`.
2. `purge-harvest --test refsnap` `firefox_maintenance_service_is_a_co_product_and_thunderbird_is_not`
   (main.rs:1105): asserts `removed[0].fingerprint.is_none()`; co-products now carry a fingerprint (fix D).
   Change to `is_some()`.
3. `purge-scan --test fs` `vendorparent::mozilla_folders_are_offered_delete_if_empty_only`: golden
   `vendorparent_firefox_tb` lacks `C:\ProgramData\Mozilla-1de4eec8-…` and `…\updates` (fix C). Add them to
   the expected paths and re-bless.

### Scores

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | precision_safe | partial_n | danger listed / presel | userdata_presel | outcomes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| vscode | **purge** | 139 | 154 | **89.0%** (137) | 89.0% | **87.7%** (135) | **100% (137/137)** | 0 | 0 / 0 | 0 | hit 139 |
| git | **purge** | 4 | 16 | **25.0%** (4) | 25.0% | **25.0%** (4) | **100% (4/4)** | 0 | 0 / 0 | 0 | hit 4 |
| firefox | **purge** | 22 | 24 | **45.8%** (11) | 29.2% | **16.7%** (4) | **100% (10/10)** | 5 | 0 / 0 | 0 | hit 22 |
| npp | **purge** | 2 | 29 | **79.3%** (23) | 79.3% | **0.0%** | n/a (no Safe item) | 0 | 0 / 0 | 0 | hit 2 |
| **macro** | **purge** | | | **59.8%** | 55.6% | **32.3%** | **100% (3 apps)** | | 0 / 0 | 0 | |

Change against the first replay (recall_listed / recall_safe / precision_safe): vscode 88.3 → 89.0 / 87.7 →
87.7 / 100 → 100; git 6.2 → 25.0 / 0.0 → 25.0 / 75 → 100; firefox 33.3 → 45.8 / 16.7 → 16.7 / 100 → 100;
npp 79.3 → 79.3 / 0.0 → 0.0 / 0 → n/a. Macro recall_listed 51.8 → 59.8, recall_safe 26.1 → 32.3.
`*_nd` recall equals plain recall everywhere.

Per-kind recall_listed for Purge: vscode Path 1/13, RegKey 136/139, RegValue 0/2. git Path 0/8, RegKey 2/2,
RegValue 2/6. firefox Path 3/7, RegKey 4/10, RegValue 4/7. npp Path 5/10, RegKey 16/16, RegValue 2/3.

### Danger items

None in any app (danger_listed 0, danger_preselected 0, userdata_preselected 0).

### False positives (offers that are not hits)

None. Every Purge offer in all four apps scores `hit` (ambient 0, other 0, gone 0). The two `UFH\SHC|0`
segment offers (git, npp) are no longer made (fix A: a baseline SHC record is not offered at all).

Hits that earn only partial coverage (not false positives, listed for reference):
- vscode: Safe `HKU\<SID>_Classes\vscode|` and `…\vscode\shell\open\command|` (REF-ANY values; the truth key
  `HKU\<SID>_Classes\vscode` is covered by the Likely CLS-PROGID item).
- firefox: Safe default values of `CLSID\{1814CEEB-…}\InProcServer32` and
  `Interface\{0D68D6D0-…,1814CEEB-…,4E747BE5-…}\ProxyStubClsid32`; Safe
  `FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB`; Safe `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` and
  `HKU\<SID>\Software\Mozilla\Firefox`; Weak `HKLM\SOFTWARE\mozilla.org\Mozilla`; Weak
  `AppData\{Local,Roaming}\Mozilla\Firefox`; Likely `ProgramData\Mozilla-1de4eec8-…\updates\308046B0AF4A39CB`;
  Weak `ProgramData\Mozilla-1de4eec8-…\updates`.

New hits from the fixes: vscode Likely FS-APPDATA `AppData\Roaming\Code` (UserData, not preselected; fix E);
git Safe whole values `UFH\SHC|1`, `UFH\SHC|2` (fix A), Safe CLS-VERBS `LibraryFolder\background\shell` and
Safe `sh_auto_file` (fix B); firefox Likely `HKLM\SOFTWARE\Mozilla\MaintenanceService` and Likely
`HKLM\SOFTWARE\mozilla.org` (fix D), Weak `C:\ProgramData\Mozilla-1de4eec8-…` (fix C).

### Remaining misses

**In M1a scope, bug or gap**
1. firefox `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` is still only partial. `Pass::vendor_container` in
   `crates/purge-scan/src/reg_software.rs` drops it at `ctx.in_baseline`, because `Baseline::has_key`
   (`crates/purge-index/src/baseline.rs`, `key_forms`) answers the WOW6432Node spelling from its 64-bit twin
   `HKLM\SOFTWARE\Mozilla` (in the baseline for Defender NMH). Needs an exact-spelling baseline check for
   delete-if-empty vendor keys; purge-plan would then make it Safe.
2. Not misses, but in-scope recall_safe gaps: firefox `ProgramData\Mozilla-1de4eec8-…` is listed but Weak,
   because `Firefox_<SID>_shortcuts.ini` and `profile_count_308046B0AF4A39CB.json` in it are offered by no
   scanner and `updates\308046B0AF4A39CB` is only Likely (FS-APPDATA would need to offer token/SID-named files
   in a vendor folder). `Mozilla\MaintenanceService` and `mozilla.org` are Likely, not Safe (plan §1.4 lists
   Maintenance Service leftovers as Safe; needs harvest-side subtree records for the co-product). npp has no
   Safe item (needs tier-A key evidence that replay does not have).

**Out of M1a scope (unchanged from the first replay)**
- vscode (17): FS-PREFETCH (5 `CODE.EXE-*.pf`), FS-TEMP (`iu-14D2N.tmp`, `vscode-inno-updater-1794413062.log`,
  `vscode-stable-system-x64`), FS-JUMPLISTS (`1ced32d74a95c7bc.automaticDestinations-ms`), FS-DOTFILES
  (`.copilot`, `.vscode` [user_data], `.vscode-shared`), REG-PRIVACY UserAssist (`Zvpebfbsg.IvfhnyFghqvbPbqr`),
  JumplistData (`Microsoft.VisualStudioCode`), SYS-APPX package state (`BackgroundAccessApplications\…`,
  `AppModel\PolicyCache\…`), beyond M1a evidence (`HKU\<SID>\Software\Microsoft\DeveloperTools`).
- git (12): FS-TEMP (`is-TU8SYANY8F-uninstall.tmp`), FS-JUMPLISTS (3 `.automaticDestinations-ms`),
  FS-PREFETCH (`BASH.EXE`, `CYGWIN-CONSOLE-HELPER.EXE`, `GIT.EXE`, `MINTTY.EXE`), REG-PRIVACY UserAssist
  (`TvgSbeJvaqbjf.Onfu`), JumplistData (2 `Microsoft.AutoGenerated.{…}` and the known-folder
  `{6D809377-…}\Git\cmd\git-gui.exe`).
- firefox (12, 4 of them partial): FS-TEMP (`2b3e1db9-….zip`, `~nsuA.tmp`), FS-PREFETCH (`CRASHHELPER.EXE`,
  `FIREFOX.EXE`), REG-PRIVACY UserAssist (`308046O0NS4N39PO`), COM-CLASS/COM-INTERFACE M1b (partial:
  `CLSID\{1814CEEB-…}`, `Interface\{0D68D6D0-…}`, `Interface\{1814CEEB-…}`, `Interface\{4E747BE5-…}`),
  REG-EXEKEYED M4 (`MediaPlayer\ShimInclusionList\false`), beyond evidence (`.shtml|` default and
  `.shtml|Content Type`). Plus the in-scope `WOW6432Node\Mozilla` above (13 firefox misses in all).
- npp (6): SYS-APPX (`AppRepository\fb764295-…_<SID>_1.rslc`), FS-TEMP (`tem5A6A.tmp`, `~nsu1.tmp`),
  FS-PREFETCH (`GUP.EXE`, `NOTEPAD++.EXE`), REG-PRIVACY UserAssist (`{6Q809377-…}\Abgrcnq++\abgrcnq++.rkr`).

Of the first replay's in-scope list, items 1, 2, 3, 6 and 7 are fixed; item 5 (ProgramData `Mozilla-…`) is now
covered at its exact path but only Weak; item 4 (`WOW6432Node\Mozilla`) remains.

Against the M1a gate (informational): danger 0 and userdata_preselected 0 met; precision_safe 100% for every
app that has Safe items (npp has none); recall_listed ahead of BCU on all four apps.

## After fixes 2 (2026-11-13)

Re-run after the test clean-up (re-blessed `nsis.plan.json` and `vendorparent_firefox_tb`, `refsnap` main.rs:1105
now `is_some()`) and the exact-view baseline fix for delete-if-empty vendor keys (`Baseline::has_key_exact_view`,
used by `Pass::vendor_container`; `wow6432node` added to the shared keys). No engine code was changed for this
run. Plans regenerated with `cargo xtask replay-all --no-score` and scored with rigtool exactly as in "How it was
produced" (purge-replay.json + bcu.json, s0/s2 from the run, `truth/deny.json`, `--sid <SID>` from run.json).
The BCU rows are unchanged from the first table. verify-gone passed for all four runs.

**`cargo xtask ci`: PASSED** (all steps):

| step | result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo test --workspace` | pass (887 passed, 0 failed, 10 ignored) |
| `cargo clippy -p purge-mcp --all-targets -- -D warnings` | pass |
| `check-deps` | pass (purge-mcp tree 38 packages; Purge crates only purge-model, purge-rpc) |
| `ui-strings` | skipped (PURGE_UT_STRINGS not set) |
| `scanner-coverage` | pass (19 scanners, 52 roots; 10 value containers equal the guard's table) |

Replay plan summary: vscode 139 items (137 Safe, all preselected; 2 Likely); git 4 (4 Safe); firefox 23 (11 Safe,
4 Likely, 7 Weak, 1 Blocked; 1 co-removed); npp 2 (2 Likely).

### Scores

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | precision_safe | partial_n | danger listed / presel | userdata_presel | outcomes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| vscode | **purge** | 139 | 154 | **89.0%** (137) | 89.0% | **87.7%** (135) | **100% (137/137)** | 0 | 0 / 0 | 0 | hit 139 |
| git | **purge** | 4 | 16 | **25.0%** (4) | 25.0% | **25.0%** (4) | **100% (4/4)** | 0 | 0 / 0 | 0 | hit 4 |
| firefox | **purge** | 23 | 24 | **50.0%** (12) | 33.3% | **20.8%** (5) | **100% (11/11)** | 4 | 0 / 0 | 0 | hit 23 |
| npp | **purge** | 2 | 29 | **79.3%** (23) | 79.3% | **0.0%** | n/a (no Safe item) | 0 | 0 / 0 | 0 | hit 2 |
| **macro** | **purge** | | | **60.8%** | 56.7% | **33.4%** | **100% (3 apps)** | | 0 / 0 | 0 | |

Change against "After fixes": only firefox moved. recall_listed 45.8 → 50.0, recall_visible 29.2 → 33.3,
recall_safe 16.7 → 20.8, partial_n 5 → 4, Safe offers 10 → 11 (all hits). Macro recall_listed 59.8 → 60.8,
recall_safe 32.3 → 33.4. vscode, git and npp are identical. `*_nd` recall equals plain recall everywhere.

Per-kind recall_listed for Purge: vscode Path 1/13, RegKey 136/139, RegValue 0/2. git Path 0/8, RegKey 2/2,
RegValue 2/6. firefox Path 3/7, RegKey 5/10, RegValue 4/7. npp Path 5/10, RegKey 16/16, RegValue 2/3.

The one new offer: firefox Safe, preselected REG-SOFTWARE `HKLM\SOFTWARE\WOW6432Node\Mozilla` (category
Registration), a full hit on the truth key that was only partial before. Its only listed child,
`WOW6432Node\Mozilla\Firefox`, is itself a Safe preselected hit.

### Danger items

None in any app (danger_listed 0, danger_preselected 0, userdata_preselected 0).

### False positives (offers that are not hits)

None. Every Purge offer in all four apps scores `hit` (ambient 0, other 0, gone 0).

Hits that earn only partial coverage (not false positives, for reference): vscode as before (Safe
`HKU\<SID>_Classes\vscode|` and `…\vscode\shell\open\command|`); firefox (unchanged list): Safe `FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB`, Safe default
values of `CLSID\{1814CEEB-…}\InProcServer32` and `Interface\{0D68D6D0-…,1814CEEB-…,4E747BE5-…}\ProxyStubClsid32`,
Safe `HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` and `HKU\<SID>\Software\Mozilla\Firefox`, Weak
`HKLM\SOFTWARE\mozilla.org\Mozilla`, Weak `AppData\{Local,Roaming}\Mozilla\Firefox`, Likely
`ProgramData\Mozilla-1de4eec8-…\updates\308046B0AF4A39CB`, Weak `ProgramData\Mozilla-1de4eec8-…\updates`.
Firefox also lists, Blocked and not preselected, REF-ANY
`HKLM\SYSTEM\ControlSet001\…\FirewallPolicy\FirewallRules|{AC21D679-A9C1-47A0-B96F-A0625A9EE822}` (a hit on a
truth leftover, plan category System).

### Remaining misses

**In M1a scope, bug or gap**
1. Fixed: firefox `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` is now a Safe full hit.
2. Unchanged recall_safe gaps (listed, not Safe): firefox `ProgramData\Mozilla-1de4eec8-…` (Weak; two files in it
   are offered by no scanner, `updates\308046B0AF4A39CB` is only Likely), `Mozilla\MaintenanceService` and
   `mozilla.org` (Likely), `AppData\{Local,Roaming}\Mozilla` (Weak), the Blocked firewall rule; npp has no Safe
   item (needs tier-A key evidence that replay does not have).

**Out of M1a scope** — identical to "After fixes": vscode 17, git 12, npp 6; firefox now 12 (was 13: FS-TEMP 2,
FS-PREFETCH 2, REG-PRIVACY UserAssist 1, COM-CLASS/COM-INTERFACE M1b 4 partial, REG-EXEKEYED M4 1, `.shtml`
values 2).

Against the M1a gate (informational): danger 0 and userdata_preselected 0 met; precision_safe 100% for every
app that has Safe items (npp has none); recall_listed ahead of BCU on all four apps.
