# M3 finish plan (final stretch, 2026-11-22)

User goal (2026-11-22): finish every open step to the M3 gate, then an overall Fable audit, fix until Fable is
satisfied. Coordinator: Claude Code (Opus 5.5). Push as you go. Host: laptop DESKTOP-K1F333G (4C/8T).

## Coordinator rulings (DECISIONS rows to be written with the gate reports)
- BL-RM S3: the R5 proxy false-absent list replaces the drift run (a drift run needs Windows Update on a rig VM).
- G1 elevated ci: the two owner tests (`gate::tests::key_actions_and_emptiness`,
  `storage::tests::strict_policy_refuses_and_renames_aside_a_tree_owned_by_a_user`) become elevation-aware (expect
  Administrators as owner when elevated) instead of an exclusion list. Elevated ci runs in the Inbound VM, not on
  the host.
- 11.3 manual SendInput test: automated from the elevated rig in the VM, with screenshots as evidence
  (`rig-m3.ps1 -Mode m3-consent`, the `sendinput-key` and `sendinput-mouse` rows; m3-uac adds real-input clicks
  inside the arming delay with UAC on).
- M2 residual (r2-m2-inline, after Fable review): every powershell/pwsh command routes Medium (profile and
  user PSModulePath load user-writable code elevated); `cmd /c` running a host executable routes Medium; `cmd /c`
  without `/d` routes Medium (HKCU AutoRun).

## Runbook (from the planner, 2026-11-22; tooling marked WRITE does not exist yet)
Rules: one VM at a time; VMPWFILE from env; official downloads; never DietPi/clone/UT. Evidence under
`E:\purge-build\gate-evidence\<step>\`. Snapshots: Inbound `rig-base`, `dirty-base`, `m2-base`, `m3-uac-on`;
Clean-Pro `rig-base-off`, `rig-base`, `m2-base`.

### A. BL-GATE -> docs/BASELINE_LOCAL_GATE.md
- A0 settled first-read W4: WRITE `rig-baseline-local.ps1 -FirstRead` (branch bl-gate-rig); run R1 (Clean-Pro), R2
  (Inbound). ~25 min each.
- A1 R5 proxy false-absent list: WRITE post-pass over R5 output; run `rig-baseline-local.ps1 -Mode R5` (needs an
  elevated host shell, no VM running). Evidence `vm\truth\baseline-local\r5-proxy.json`.
- A2 R3 replay: WRITE `vm/truth/bl.sh` (branch bl-gate-score); `PURGE_RUNS_DIR=<main>\vm\runs bash vm/truth/bl.sh
  replay`. 1-1.5 h CPU.
- A3 R4 campaign, exact baseline hidden: WRITE rig `-HideExact`, data root, `-ExpectTrust` through m1b modes
  (branch bl-gate-rig). First an exact smoke `m1b-app -App 7zip` (baseline_trust exact in run.json). Then blm-
  (merged) and bll- (local) m1b-apps + m1b-traps on Inbound and Clean-Pro. ~7-8 h. Score `bl.sh evaluate`.
- A4 S2/S3/S5/W1: cite gate M. A5 write the report + harvest subset test (branch bl-gate-score).

### B. M3 gate -> docs/M3_GATE.md (criteria G1-G14, M3_DESIGN section 12)
- B1 replay-all (~47 min) + the two ignored xtask replay tests (~47 min more).
- B2 G1 ci unelevated (host) + elevated (Inbound VM).
- B3 G2 benches, quiet host, Defender on: warm (`--bare out\bare`), first-launch x5. WRITE `--real-engine`,
  `icons_visible` marker, S3 2,000-item timer.
- B4 G3/G10 m3-broker (exit codes 20-27, planted dirs, off-system-volume copy, user-writable copy). Tooling: done,
  branch m3-rig-sec (vm/RIG.md section 14; 21 cases, exit 27 excluded with its reason in `vm/truth/m3-sec-expect.json`).
- B5 G4 m3-consent: real broker TaskDialog UIPI probe + SendInput test. Tooling: done, branch m3-rig-sec (medium
  SendInput/PostMessage/SendMessage/UIA at both real dialogs, high control per method, screenshots per step).
- B6 G5 m3-uac from `m3-uac-on`: No -> 1223, Yes -> full flow, standard-user refusal, secure-desktop dialog
  (arming, paging, footer code, foreground). Tooling: done, branch m3-rig-sec (extends rig-m3.ps1).
- B4-B6 run commands (host, unelevated, no other VM running; release builds only, never the rig-exec engine):
  ```
  $env:VMPWFILE = '<pw file>'; $t = '<main checkout>\target'
  .\vm\rig-m3.ps1 -Mode m3-broker  -Engine $t\release\purge-engine.exe -Broker $t\release\purge-broker.exe   # ~40 min
  .\vm\rig-m3.ps1 -Mode m3-consent -Engine $t\release\purge-engine.exe -Broker $t\release\purge-broker.exe   # ~45 min
  .\vm\rig-m3.ps1 -Mode m3-uac     -Engine $t\release\purge-engine.exe -Broker $t\release\purge-broker.exe -UiPublish $t\ui-publish
  powershell -NoProfile -File vm\truth\m3-sec-score.ps1 -Mode broker|consent|uac -Evidence E:\purge-build\gate-evidence\m3-<mode>
  ```
  Evidence `E:\purge-build\gate-evidence\m3-broker|m3-consent|m3-uac\` (an older one is moved to `<dir>-old-<stamp>`).
- B7 G6/G7/G12 m3-e2e on the M1 apps (VS Code system + user, Git, Firefox+Thunderbird, Notepad++, 7-Zip, one M1b
  service/task app) + failed uninstaller 1603/3010. WRITE UIA driver, scorer, broker timing records.
- B8 G8/G9 m3-owner, m3-recover (crash at every step), allow_irreversible, Restart Manager, System Restore. WRITE.
- B9 G11 m3-clean-start + Inno setup install/uninstall on Clean-Pro. WRITE.
- B10 G13 re-run M1b scan + executor gates on the M3 commit (~10 h; cut allowed: G2 rig-base + G5 elevated).
- B11 G14 M3-R3 Fable review, then docs/M3_GATE.md (M2_GATE format).

### Parallelism
Benches and R5 alone on a quiet host. VM campaigns + script writing OK; builds with CARGO_BUILD_JOBS=2. Never two
VMs. Host replays (A2, B1) can overlap A3 but not B7 timings.

### Needs the user
- An elevated host shell for A1 (R5) only (everything else elevated runs in a VM).
- Keyboard-only + Narrator pass (M3_DESIGN 11.3): human judgement.
- SmartScreen/SAC on unsigned binaries: reported; code signing is the user's open item.

## Status
- Done: cold bench PASS (559.7 ms), desktop trial PASS, unelevated ci PASS, M3-R2 cleanup, S2 test (bc0d558).
- In progress: r2-m2-inline (rework after Fable), r3-history, bl-gate-rig, bl-gate-score.
