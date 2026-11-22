# BL-GATE report (local baseline and the nearest-build union, wave 6)

- Dates: R4 campaign 2026-11-22, R3 replay and evaluation 2026-11-22/23, W4 first reads 2026-11-23.
- Procedure: `docs/BASELINE_LOCAL_DESIGN.md` §8 (runs §8.2, safety §8.3, worth §8.4); runbook `docs/HANDOFF-baseline.md`
  "BL-GATE runbook"; rig `vm/RIG.md` §8a and §12.9; scorer `vm/truth/bl.sh` + `vm/truth/bl_eval.py` (self-test 19/19),
  which runs `vm/truth/m1b.sh` on the R4 sets.
- Decisions and accepted limits: `docs/DECISIONS.md`, the "(coordinator)" rows of 2026-11-22/23 named below.
- Rig host: the laptop. VMs Inbound-Win11-Test (Windows 11 Enterprise LTSC 26100.1742; snapshots `rig-base`,
  `dirty-base`) and Purge-CleanPro (Windows 11 Pro 26340.9882, `rig-base`).
- Engine: one release build for R3, R4 and the W4 first reads, sha256 `ccf1f5212a71d34e…`, built at `8dea299` (the
  stderr-lock fix). Branch `baseline`.
- Evidence: `vm/truth/baseline-local/` (W4 first reads, gate M reports), `C:\purge-build\gate-evidence\bl-gate\`
  (`bl\`: the evaluation output with `bl-score.json`, R3 plans and the R4 `m1b.sh` scores; `bl-evaluate.out`,
  `r3-replay.out`, `w5-proxy-r3.txt`, `a0\`, `a3\`, `w4-diagnostics\`).

## 1. Verdict

**BL-GATE: PASS on safety (S1 to S5); worth (W1 to W5, which do not gate): W1 met, W2 and W3 measured, W4 met on Inbound and a W fail on Clean-Pro, W5 not measured on the host.**

- `bl.sh evaluate`: **S criteria PASS, 0 failing S rows** (2026-11-23).
- The feature ships **presence-only**, as built (design §4.3 "As built"): below Exact no site consumes inferred absence.
  W2's own rule (below 50 %: presence-only) confirms that choice; nothing in this gate argues for wiring the A side.
- Measured misses, each with a ruling: W3 1.13 % (limit 1 %), W4 on the Clean-Pro VM (323 s, budget 120 s).
  W5 on the corpus: the merged view changes 0.18 items per run, under the "one per program" bar, so the report says
  the host gains little and why (section 4). Section 5 lists the follow-ups.

| Criterion | Result | Key numbers |
|---|---|---|
| S1 R3 | pass | 0 flips over 39 of 39 runs, merged and local; 0 new items listed Blocked only |
| S1 R4 | pass | merged and local, clean + dirty + Clean-Pro: 63 RUN/K1/K2/K3/K9 rows each, all pass or explained; `danger_offered` 0 and `danger_listed` ≤ the exact gate for every app (design "= 0" restated, ruling 2026-11-23); every trap set met. Other m1b.sh rows below Exact: 3.4 |
| S2 | pass | the seven areas marked `merged` in `kb/baselines/view.json` pass S2 on both VMs (gate M) |
| S3 | pass (accepted outcome) | no area is marked `local`: Local is presence-only |
| S4 | pass | L3: the five pinned references (7zip, firefox, git, npp, vscode; 5 of the 39 runs, no M1b-set run has a pinned exact plan) byte-identical; L5: 78 plans below Exact checked, 0 violations |
| S5 | pass | seal `complete` on both VMs (gate M and the first reads) and on the host (R5, with 24 of 168 S4 packages unparsed, within §3.4's floor; follow-up 5); `an_unreadable_source_fails_its_line` passes |
| W1 | pass | gate M: 99.966 % (R1) / 99.953 % (R2) pooled over the marked areas (restated W1, DECISIONS 2026-11-21) |
| W2 | 0/7 = 0 % → presence-only | as built; candidates listed in 4.2 |
| W3 | 7/620 = 1.13 % (W) | measured miss, ruling 2026-11-23; local 0 % |
| W4 | R2 pass, **R1 W fail** (measured miss) | Inbound 89.93 s, Clean-Pro 323.25 s (budget 120 s); host 22.8 s cold (budget 30 s, gate M engine) |
| W5 | **not measured on the host**; corpus proxy 0.18 per run | ruling 2026-11-23 (4.5) |

## 2. Runs

| Run | What | Result |
|---|---|---|
| A0, W4 | settled first read, one build per boot (`rig-baseline-local.ps1 -FirstRead`) | R2 89.93 s, R1 323.25 s (rerun 2026-11-23 with the 120 s budget, `cab6c46`) |
| A3 | exact smoke (`blx-m1b-7zip`) | `engine.hello` expected/asked exact, `baseline_trust` Exact, every phase ok |
| R3 | `bl.sh replay`: 39 frozen M0/M1a/M1b runs × views exact, none, merged, local | 156 replays, all exit 0 |
| R4 | M1b apps + traps, exact baseline hidden (`blm-`, merged) or no shipped baseline (`bll-`, local) | 70 runs, all ok (one rerun, 3.2) |

Gate M (R1, R2, R5; `vm/truth/baseline-local/bl-r1-cleanpro.json`, `bl-r2-inbound.json`, `r5-host-*.json`) is cited
for S2, S3, S5 and W1.

## 3. R4 (S1)

### 3.1 Sets

| Set | VM, snapshot | Merged runs | Local runs |
|---|---|---|---|
| clean | Inbound `rig-base` | `blm-m1b-*` (11 incl. 3 null) + traps | `bll-m1b-*` + traps |
| dirty | Inbound `dirty-base` | `blm-m1bd-*` (10) + traps | `bll-m1bd-*` + traps |
| cp | Clean-Pro `rig-base` | `blm-m1bcp-*` (11) + traps | `bll-m1bcp-*` + traps |

Every warm-up job reported the expected trust (`engine.hello` `baseline_trust` Merged or Local) before the app ran.
`danger_listed` per app never exceeds the exact M1b gate's (`truth/m1b-evidence/score-<set>.json`); the only kept
danger item is the deny-listed `bam\State\UserSettings` value, listed Blocked, as in the M1b gate.

### 3.2 Rulings and reruns

- **Empty plan, clean/node** (ruling 2026-11-22, Fable-reviewed): K1/K3 "empty plan" in both views is a W3-R4 recall
  cost: RUN passed, offered 0 and `danger_listed` 0, the exact gate's plan was only `UFH\SHC` slot values (Windows'
  own below Exact, BL-FIX-UFH), and the R3 replay of that gate run with the same view offers nothing.
- **Truth noise, dirty/temurin merged** (ruling 2026-11-22): the first run's truth held three Windows items
  (`InstallService`, `Notifications\Settings`, `SmartOptOut`) that no null run caught; the app was rerun once alone
  (`campaign-20261122-210516`), the first run kept aside. No truth rule was added.
- **Rig fixes during the campaign** (ruling 2026-11-22): the Clean-Pro Store update policy (`AutoDownload=2`, the S4
  hash moved at every boot before), the data-root label for the engine's own caches in rigtool, and the run names in
  the scorer. Both VMs ran at once for correctness rows only; E: then filled (both paused, no data lost) and the rule
  became "two VMs only with about 25 GB free on E:".

### 3.3 Binding

One engine (`ccf1f521…`) for all 70 runs. The runs name three commits that differ only in rig and scorer files, not in
the engine: `8dea299` (Inbound), `5abba7d` (Clean-Pro, + the Store policy), `3585193` (the temurin rerun, after the
merge). `m1b.sh`'s BIND row fails by design here (it compares against the M1b gate's budgets and replay evidence);
the BL scorer does not use it.

### 3.4 Other m1b.sh rows below Exact

The BL scorer reads RUN, K1, K2, K3 and K9. The other `m1b.sh` rows that fail in R4, in both views:

- **K1/K3 to K6 on clean/node:** the empty plan of 3.2; K4 to K6 fail for the same empty plan.
- **BIND:** by design (3.3).
- **K8, four rows per view:** `clean/vcredist` and `dirty/vcredist` preselect 1 item (limit 0); `clean/python` and
  `cp/python` show no Launcher suggestion (limit at least 1). The item is FS-PKGCACHE, Safe, on an empty
  `Package Cache\{bundle}` folder. It appears in all three sets of vcredist and in python, and the SYS-BURNDEPS
  suggestion is missing.

Attribution (Fable review finding 1; investigation 2026-11-23): **not the view, two engine regressions from M3 work.**

- **Exact-view controls show it too.** `blx-m1b-vcredist` and `blx-m1b-python` ran on the gate engine, Inbound
  `rig-base`, with the exact view, and both show the same item.
- **The folder.** Since `65347f2` (M3-R2 S4), an elevated engine starts the uninstaller with its working directory
  set to the uninstaller's own folder. For a Burn bundle, that folder is the Package Cache folder. Burn exits 0, but it
  leaves the folder empty and schedules its deletion in `PendingFileRenameOperations` (seen in the post snapshots).
  The scan then reports, correctly, an empty folder that exists.
- **The suggestion.** Since `59ae960`/`957c1be`, the live registry reader opens `HKU\S-1-5-18\Software\Classes` as an
  ordinary key. It is a registry link, and the read is refused as a reparse point. The MSI ownership index is then
  incomplete for Burn, so SYS-BURNDEPS withholds the suggestion (engine log in `blx-m1b-python/run.log`). Replays
  cannot show this, because the snapshot does not capture the link.

Neither cause depends on the baseline view, so they do not count against S1. They are M3 regressions: the fixes, and
the `m1b-vcredist`/`m1b-python` re-runs on the fixed engine, belong to the M3 gate (B10, the M1b re-runs).

## 4. Worth (W1 to W5)

### 4.1 W1

Gate M, restated W1 (DECISIONS 2026-11-21): 99.966 % (R1) and 99.953 % (R2) pooled over the seven marked areas; scope
coverage (88.6 % / 95.7 %) is reported, not judged (most misses carry a version, hash or package name under
`CurrentVersion`).

### 4.2 W2 (0/7)

The candidates the exact view offers and none does not: git's `HKLM\SOFTWARE\Classes\sh_auto_file` and
`LibraryFolder\background\shell` (runs git, r2-git) and the vscode ProgID `HKU\<sid>_Classes\vscode` (vscode, r2-vscode,
r2-vscode-user). Only absence can promote them; presence-only never does. The rule's own consequence (presence-only)
is what ships.

### 4.3 W3 (1.13 %, measured miss)

All 7 blocked items come from `r2-vscode-user`: `HKU\<sid>_Classes\.ini`, `.log`, `.ps1`, `.psd1`, `.psm1`, `.ts`,
`.txt`, offered by the exact view (REF-ANY) and listed Blocked by the merged view because the neighbour baseline
(Professional 26340) holds them as Windows' own. The local view blocks none. Kept: blocking what a neighbour build
ships is the safe side (ruling 2026-11-23).

### 4.4 W4 (R2 pass, R1 W fail, measured miss)

| | Inbound (R2) | Clean-Pro (R1) |
|---|---|---|
| manifests | 18,489 | 31,647 |
| settled first read | **89.93 s** | **323.25 s** |
| read (thread time, 4 threads) | 315.9 s | 1,195.1 s |
| expand + parse | 19.0 s | 63.3 s |
| settle | CPU 4.1 %, standby emptied, offline | CPU 6.9 %, standby emptied, offline |

Every Clean-Pro first read on record (evidence `w4-diagnostics\`; the `_old` directory names are the time a run was
moved aside, not the time it ran):

| Run | Engine | What differs | Seconds | CPU at start | Uptime at build |
|---|---|---|---|---|---|
| A0 try 1 (2026-11-22) | `a6457922` (gate M) | | 356.37 | 2.7 % settled | 719 s |
| A0 try 2 | `a6457922` | | 202.04 | 27.5 %, **not settled** | 1,105 s |
| **gate** | `ccf1f521` | | **323.25** | 6.9 % settled | 655 s |
| diagnostic | `fbc9f2c6` | patch on the pipeline path, which the CLI build does not use: same as the gate | 327.72 | 7.8 % settled | 660 s |
| diagnostic | `549598c3` | the same, a pipeline-only patch | 200.88 | 27.3 %, **not settled** | 1,103 s |
| diagnostic | `273ef74b` | CLI build, 16 threads, background mode | 334.31 (read 5,125 s thread time) | 7.2 % settled | 666 s |
| diagnostic | foreground | CLI build, 4 threads, out of background mode | 138.86 (read 480 s thread time) | 7.3 % settled | 471 s |

What this shows: more threads do not help (the reads are serialised: four times the thread time, the same wall time).
Out of background mode the build is the fastest on record. But the two builds that started late (uptime about 1,100 s,
after a 600 s wait for a CPU that did not settle) took about 200 s in background mode, so something that ends some
15 to 20 minutes after boot (an inference: Defender's or the indexer's post-boot work on the same files) also weighs on
the time and the settle criterion does not capture it. Background mode's share is therefore between about 30 % (139 s
against the late builds' 200 s) and 57 % (against the gate's 323 s); "Defender and the virtual disk" for the rest is
an inference, nothing here isolates it.

On real hardware (R5, the desktop, 8 CPUs, **gate M engine `5408fbeb…`**, Professional 26100.9711) the cold build in
background mode is 22.8 s (budget 30 s), peak 298.7 MB (300 MB), file 11.0 MB (15 MB). The other §5 budgets: warm load
of the view 0.30 to 0.33 s cached and 1.24 s first load on the laptop (BL-CACHE, budget 1.5 s); the `baseline info`
times in the build records (2.8 to 4.0 s) are a whole process that re-reads and checks the text file, not the view
load (DECISIONS 2026-11-21); the source-id check (budget 0.3 s) is not measured on its own.

**W4 is a W fail on Clean-Pro (2.7 times the budget), recorded as a measured miss** (ruling 2026-11-23). Kept: background
mode; a scan never waits (trust None with a warning, rescan offered), and a waiting scan raises the build out of
background mode. Follow-up (M4): the per-handle I/O hint Low instead of very-low, then R1 again, with the uptime
recorded and a settle that also waits for the post-boot scans.

### 4.5 W5 (not measured)

W5 asks for scan plans of ten host programs, merged against none, in the elevated R5. That run was not made (this
session runs unelevated; gate M's elevated R5 measured the build only), so **W5 is not measured** (ruling 2026-11-23).
The proxy below is VM leave-one-out runs, not the host's two-neighbour view, and is reported only.
Proxy over the 39 R3 runs (`w5-proxy-r3.txt`): the
merged view removes 7 offered items (the W3 keys) and adds no Likely key, 0.18 changes per run; the local view
changes nothing. **The host likely gains little from the presence-only view, and why:** the no-baseline plans already
keep Windows-owned keys out (deny lists, ownership proofs, L5), so presence only matters where an app's candidate
coincides with a key a Windows build ships; absence, the side that would add Likely keys, is not used below Exact.

## 5. Follow-ups

1. W4: per-handle I/O hint Low for the S1 reads (M4), then R1 again.
2. W5 on the host (elevated R5 with ten programs), with the M3 or M4 host benches.
3. Product question for the user: whether the background local-baseline build stays on by default in v1, given W5.
4. Lifting the cap (design §8.5): the drift run or the R5 proxy false-absent list (review BL-RM S3) is a precondition
   there, deferred from this gate (ruling 2026-11-23).
5. R5 S4: 24 of 168 inbox packages failed to parse on the host (`appx.rs`), from gate M; still open.
6. The two engine regressions of 3.4 (uninstaller working directory, the S-1-5-18 classes link): fixed and re-run in
   the M3 gate (B10).
7. Design §5 still says "2-vCPU VM" for the W4 budget; the rig VMs have 4 CPUs (the budget was set for 4, ruling
   2026-11-23). Fix the text with the next design edit.
