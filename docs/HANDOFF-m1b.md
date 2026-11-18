# M1b handoff

## Paused for the laptop migration (2026-11-19 00:30)

- Gate5 fix done and pushed (834819c + 8e1a1d2); Fable check R7 clean (no blocker). Smoke run on Clean-Pro python:
  Defender wait ended current after 3 busy answers + 1 exit-0 update, 131 s; snap0/snap2 versions equal.
- G7 precheck on a settled host at 8e1a1d2: added scan +1.80 s, harvest +1.86 s (limit 2.5), ownership.components max
  1.22 s (limit 1.5): the gate5 K14 miss was host load. Evidence `E:\purge-build\gate-evidence\m1b-g7-precheck\`.
- Scan campaign 4 at 8e1a1d2, stopped on the user's request after G4a: G1 replay pass, G2 11/11 ok, G3 10/10 ok,
  G4a rig-base traps 1/1 ok. Not run: G4 dirty-base traps, G8, G7, `m1b.sh`. Logs `E:\purge-build\gate-evidence\m1b-gate6\`;
  runs still in `vm\runs`.
- Next: migrate the rig to the laptop (`docs/MIGRATION-laptop.md`), then continue campaign 4 or rerun it in full there.

## Current state (2026-11-18 17:30): scan gate fix round 3, then full rerun

- Branch `m1b` head = this commit (on c388dd1), pushed to origin on the user's request 2026-11-18.
- Scan campaign 1 (gate3, at ee43fa2): 133/153. Causes: K1 counted a Blocked, deny-listed bam value as danger; the
  Python Launcher suggestion could never fire (CPython writes no package provider record); dirty-base node was
  preinstalled; dirty truth noise (`%TEMP%\<hex>.tmp`, Steam logs); K14 measured with no disk cache and an unfair
  program; co-product harvest rebuilt every index. Evidence `E:\purge-build\gate-evidence\m1b-gate3\`.
- Fixes: engine ba48ae7 (Burn link via kb `burn_link`, shared co-product indexes, `msi_table_cache` timing line); rig
  b89ffde, a954d90; Fable reviews R4d, R5, R5b (`docs/reviews/m1b/`) and fixes 5a6fd2b, c388dd1. User rulings in
  DECISIONS M1b (2026-11-18): K1/K8 count danger_offered; node dropped from G3 + RUN invalid-run check; a ReportOnly
  `suggest_uninstall` item is a notice scored only by K8; K14 needs a warm disk cache and a like-for-like program;
  `install\install.ps1` was run on the host. Unelevated `cargo xtask ci` PASS at c388dd1 (scheduled task with
  `/rl LIMITED /it`; `runas /trustlevel` did not start).
- Scan campaign 2 (gate4, at c388dd1): 148/153. Only K1, K3-K6 clean/temurin failed: a Defender signature update
  landed inside the capture window of 4 of 8 clean runs (232 MB of definitions about 20 s after snap 0), and its
  items were labelled leftover; temurin's correct empty plan then failed. G7 program: Virtual Desktop Service
  `HKLM|64|{03A5EEF8-32BE-429C-AA3F-DE8C632F0218}` (the only candidate with one root in both engines and no
  co-product). Evidence `E:\purge-build\gate-evidence\m1b-gate4\`.
- User ruling: proper fix + full rerun. In progress: Defender ambient rules in `truth/labels/_m1b-noise.json`, the guest
  waits for Defender updates before snap 0 and records the signature version at snap 0 and snap 2, and a RUN check
  voids a run whose version changed. Then: Fable check, unelevated ci, full scan campaign, then G5/G6, M1B_GATE.md.
- Infrastructure lessons: keep the guest password file (VMPWFILE) outside any Temp or scratchpad folder
  (the old copy in a Temp scratchpad was wiped); power off leftover rig VMs before each campaign step (low-memory
  reaper); VirtualBox start failures with `SystemExtendedHandleInformation failed: 0xc0000004` mean a host handle leak
  (two orphaned `find /` processes held 9 M handles).
- UI alpha rebuilt on c388dd1: branch `ui-alpha` 5d7df3c, `Desktop\Purge-ui-alpha-2.zip` (notices for uninstall
  suggestions, never selectable).
- Future-version ideas: `docs/FUTURE_IDEAS.md`.

## Earlier state (2026-11-17 16:30): paused before the gate campaign

- Branch `m1b` head 59ac127, local only (not pushed since f209730). Tree clean.
- Done: all 38 design packages (waves 0-6); Fable reviews R1, R2a, R2b, R3a, R3b, R4, R4b, R4c with every finding
  fixed or recorded (`docs/reviews/m1b/`); 7-Zip smoke on Inbound 44/44, 0 escapes; frozen truth for powershell and
  temurin; K5 pairs reach 42 / 44 kept_owner.
- Unelevated `cargo xtask ci` PASSED at b1fcd97 (log `E:\purge-build\ci-unelev.log`). G0 passed at abe3645 (elevated,
  five known skips). G1 replay passed (K16 unexplained 0, K7 7-Zip key offered).
- Paused by the user during the G1 rerun at 59ac127; no VM ran. Only `vm/` changed since G0 (59ac127: guest checks
  pinned installer hashes; caused G3's Python failure, a stale 3.13.1 installer on dirty-base).

### To resume the gate

1. Scan campaign at the m1b head (Haiku babysits, stop on any non-infrastructure failure): G1, G2 (rig-base), G3
   (dirty-base), G4 traps both bases, G8 Purge-CleanPro, G7 budgets on the host vs M2 head 3265797, then
   `bash vm/truth/m1b.sh evaluate`. Set `RIG_CACHE_DIR=<main checkout>m\cache` (a worktree has no cache),
   `PURGE_RUNS_DIR=<main checkout>muns` for G1. One background shell and one waiter only: the Claude Code memory
   reaper killed a long run once (DietPi, the user's VM, may be running; never touch it).
2. Executor campaign: G5 (`vm/rig-m1b-exec.ps1` m1b-x-elevated, -fidelity, -traps, -undo-traps) and G6
   (m1b-x-crash, 74 rounds incl. 15 power-offs), scored by `vm/truth/m1b-exec.sh`.
3. `docs/M1B_GATE.md`, DECISIONS, ask the user before pushing `m1b`. Evidence under `E:\purge-build\gate-evidence\`.

### Also done this session, outside the gate

- UI alpha (scan + review, no deletes) on local branch `ui-alpha` 9369255; `Desktop\Purge-ui-alpha.zip`.
- Local-baseline design (`docs/BASELINE_LOCAL_DESIGN.md`/`.json`, open questions decided in DECISIONS "Post-M1b"):
  implement after the gate. Release-build baseline packs = future maintenance.
- M3 notes: test broker elevation with the UAC prompt on (the host runs ConsentPromptBehaviorAdmin=0); the
  `kbaselines` admin-only check and `PURGE_KB_DIR` restriction go to the M3 broker review; UI alpha's wanted engine
  changes (object display name/program in the scan output, typed warning kinds, firewall names in `plan show`).

Milestones after M1b: local baseline + M3 (UI + broker).

---

## Earlier notes (2026-11-16, before wave 2)

Pickup notes for whoever continues M1b. The design is `docs/M1B_DESIGN.json` (one-page summary `docs/M1B_DESIGN.md`).
M2 is closed: `docs/M2_GATE.md`, branch `m2` pushed to origin.

## Where things are

- Branch `m1b` (local only, not pushed), on top of `m2`. Head: "M1B-MODEL: object scope, object digests, M1b
  fingerprint facts, typed ExecOps".
- Done: wave 0 (M1B-S0 scaffolding, M1B-SPIKE) and all of wave 1: M1B-MODEL, M1B-SOURCE, M1B-WIN-MSIDB, M1B-WIN-SCM,
  M1B-WIN-TASK, M1B-WIN-FW, M1B-KB, M1B-RIG-GUEST. Each was written by its own agent in a worktree and cherry-picked
  onto `m1b`; each agent's own `cargo xtask ci` passed.
- `cargo xtask ci` over all of wave 1 together (574f3af): all steps passed.
- Stopped on purpose before review R1 (the Fable review after wave 1). Nothing of wave 2 has started.

## Next step: review R1

One Fable (medium effort) agent reviews wave 1, in the form of `docs/reviews/m2/*.md`, writing
`docs/reviews/m1b/r1-review.md`. Scope: `git diff 3265797..m1b` minus docs and vm/, against `review_points` R1 in the
design. Add these points collected while merging:

1. `ItemOutcome::PendingDelete` (new, M1B-MODEL): a service with another open handle is only marked for delete
   (spike), so the design's "use PendingReboot" was wrong. Coordinator's view: accept. Reviewer to confirm.
2. M1B-WIN-SCM refuses more than the design: running services, anything not a plain own/shared-process Win32
   service, an SDDL without a DACL or with a NULL DACL. svchost services report status type 0x30 vs config 0x20;
   the predicate accepts it.
3. M1B-WIN-TASK refuses to register XML containing `RegistrationTrigger` (it would start the task on undo). The
   match is broad (any mention). Not verified: whether a re-registered task with a past time trigger and
   "start when available" runs at once.
4. M1B-WIN-FW maps some fields by inference from this host's rule strings, never re-created on a VM (Edge,
   Defer=App, ICMP, LSM, LOM, local addresses, Profile=Domain); 218 of 1,080 host rules are refused as not exactly
   restorable. WQL id escaping and the exact-id check after a case-insensitive match.
5. Three wrappers each define their own `WinError` (msi_db, scm, taskschd, firewall); purge-win does not depend on
   purge-model, so local types (`RawTask`, `RuleString`, scm types) must be mapped in wave 2 (M1B-SOURCE-IMPL,
   M1B-X-FOUND).
6. M1B-KB: `{C48C7FCF-...}` is named IAccessibleAction in the Windows registry; possibly IAccessibleDocument in the
   IAccessible2 IDL (unchecked). `shared-iids.json` is an object `{iids, shared_proxy_clsids}`, not an array:
   M1B-GUARD must read that shape. M1B-KB added `flate2` as a dev-dependency to purge-guard (outside its files).
7. M1B-MODEL edited files outside its list (match arms marked `// M1b: wired by <id>` in purge-exec, purge-policy,
   purge-scan, purge-plan); check none changes M2 behaviour.
8. M1B-SOURCE: fixture rejects unknown top-level keys and oversized cells drop whole rows.

Then fix the review's B/S findings (Opus high), then wave 2.

## The spike changed the design (vm/spikes/m1b/README.md, RESULT.json)

All three object kinds re-create exactly. Where it contradicts the design, the spike wins:
- Firewall: delete by WQL on InstanceID (exactly one match, exact id), re-create by create-only PutInstance with
  filters as context values. `FIREWALL_RESTORE_EXACT = true`; open question 2's fallback is not needed.
- Task: register from XML alone, no SDDL argument. TaskCache `Tree\Id`, `DynamicInfo`, `Hash`, 5 bytes of `Triggers`
  are regenerated: rigtool execdiff must ignore them (K10).
- Service: create from the raw ImagePath in the key backup; config2 only where the backup has the value; DACL only;
  write back the remaining backed-up values. Delete closes its own handle before the re-open check. A stored service
  password is lost on delete and invisible to any comparison: `partial` comes from the definition
  (`account_builtin`). A task with a stored password cannot be restored (`PasswordNeeded`).
These must be applied by M1B-X-FOUND, M1B-X-SERVICE, M1B-X-TASK, M1B-X-FIREWALL (wave 2/3): the design text for those
still says otherwise. Decisions are in `docs/DECISIONS.md` section "M1b".

## Rig work owed (for M1B-RIG-HOST / M1B-RIG-EXEC)

- 15 M1b elevated tests written but not run anywhere: `crates/purge-win/tests/scm.rs` module `elevated` (6),
  `crates/purge-win/tests/firewall.rs` module `rig` (9), plus the M2 pair already in the rig. Add the M1b ones to the
  rig's elevated list and run them on Inbound.
- New app hashes (PowerShell 7.6.10, Temurin 21.0.13+9, Python 3.13.17) need entries in the host cache manifest
  `cache-sources.json`; until then the guest does not check them.
- `vm/guest/m1b-traps.ps1` has a `between` phase (after harvest, before uninstall) the host does not run yet.
- KB gaps needing VM captures are listed in `kb/README.md` (IAccessible2_3, x86 VC++ runtime, Java Access Bridge,
  .NET hosting, per-user Python Launcher).

## Open questions (work proceeds on the defaults)

From `docs/M1B_DESIGN.md`: (1) preselect services/tasks/firewall rules only when recorded at harvest, program gone,
full undo; (2) settled by the spike; (3) services with a stored-password account: partial, never preselected;
(4) Temurin 21 LTS JDK MSI, PowerShell 7 LTS MSI (pinned 7.6.10); (5) +2.5 s warm on scan and harvest accepted.

## How the work is run

- Model routing (user-agreed): critical packages written by Opus (high effort); Fable (medium) reviews at R1-R4 and
  writes designs. The user's rule: important work is reviewed by Fable while Fable is available; it trumps saving
  tokens. Medium: Opus medium; trivial: Sonnet; VM babysitting: Haiku.
- One agent per package, `isolation: worktree`; the brief starts with `git reset --hard <m1b head>`; one commit per
  agent; the coordinator cherry-picks onto `m1b`, runs `cargo xtask ci`, removes the worktree and its build folder.
- Builds: `CARGO_TARGET_DIR=E:\purge-build\<name>`, `CARGO_BUILD_JOBS=4` (C: is nearly full; the host froze twice on
  2026-11-16 under parallel agents plus a VM). One VM at a time. At most four agents building at once.
- VM rules: only "Inbound-Win11-Test" and "Purge-CleanPro" (Clean-Pro now has snapshot `m2-base`, no D:). Never touch
  "DietPi..." or "haiku". Password only via the password file in `$env:VMPWFILE`, never printed or committed.
  Official vendor downloads only. No UT strings or code; no egui.
- Nothing is pushed or merged without asking the user.

## What is left in M1b

Package entries, contracts and acceptance lists are in `docs/M1B_DESIGN.json`; C = critical, H = high, M = medium.

| Step | Packages | Notes |
|---|---|---|
| R1 | Fable review of wave 1, then fixes | next step; points listed above |
| Wave 2 | M1B-GUARD (C), M1B-POLICY (C), M1B-SOURCE-IMPL (H), M1B-OWNERSHIP (C), M1B-SYSOBJ (C), M1B-RIGTOOL (H), M1B-X-FOUND (C) | SOURCE-IMPL and X-FOUND map the wrappers' local types; X-FOUND applies the spike's service/task facts to C-DEF |
| Wave 3 | M1B-HARVEST (C), M1B-FRAMEWORK (C, integration), M1B-PLAN (C), M1B-X-SERVICE (C), M1B-X-TASK (C), M1B-X-FIREWALL (C) | HARVEST holds the 7-Zip MSI fix; X-* follow the spike, not the design text |
| R2 | Fable review of waves 2-3, then fixes | guard, policy, ownership, harvest, framework, executor modules |
| Wave 4 | M1B-S-COM, S-SHELLEX, S-SERVICE, S-TASK, S-FIREWALL, S-BURN, S-MSIREG, S-PRIVACY, S-APPX (all C), M1B-S-DIAG (H), M1B-X-INTEG (C, integration) | the new scanners; no new whole-registry or whole-volume walk |
| R3 | Fable review of wave 4, then fixes | scanners, executor integration |
| Wave 5 | M1B-SCAN-INTEG (H, integration) | catalog, budgets check (`xtask no_new_walks`) |
| R4 | Fable review of wave 5, then fixes | integration, trap list, truth labels |
| Wave 6 | M1B-RIG-HOST (M), M1B-RIG-EXEC (H) | rig owed items listed above go here |
| Wave 7 | M1B-GATE (H; Haiku babysits the VM campaign) | 6 apps on the clean and dirty VMs, 26 traps, typed actions, crash matrix with 15 power-off rounds, budgets, M1a replay |
| Close | gate report `docs/M1B_GATE.md`, decisions, handoff, ask before pushing `m1b` | |

Rough size, from M2's pace: 2 to 3 days of continuous running, most of the uncertainty in the gate.

## Milestones (docs/ENGINE_PLAN.md section 11.1)

| M | Scope | State |
|---|---|---|
| M0 Hygiene + rig | repo, rig, baselines, frozen per-app numbers | done |
| M1a Engine dry run I | first scanner set, dry-run plans for VS Code, Git, Firefox, Notepad++ | done; gate m1a.6, branch `m1a` pushed |
| M2 Executor | quarantine, backups, journal, undo, recovery, `rig-exec` CLI | done 2026-11-16; branch `m2` pushed; `docs/M2_GATE.md` |
| **M1b Engine dry run II** | MSI ownership, Burn, COM, services/tasks/firewall (scan + execute + undo), more scanners; 7-Zip, Python, Node, VC++, PowerShell, Temurin | **in progress: wave 1 done, paused before R1** |
| M3 UI + broker | WinUI shell (S1-S4, S7), elevated broker with consent dialog, per-user runner, launch-time gates; WinAppSDK upgrade before 2027-04-29 | next, per the user's order; the sandbox dev build is a stopgap, not M3 |
| M4 Coverage | remaining scanners, external and forced modes, pre-harvest cache, KB packs; corpus recall gates | later; also receives items M1b moved out (cached MSI files, MSI Directory/File ownership, VS Code user-beside-system, AppX all-users) |
| M5 Observation | ETW during uninstalls | later |
| M6 AI agent | `purge-mcp`, propose APIs, KB lifecycle | later |
| M7 v2 extras | install-and-trace, startup manager, Steam/Scoop/Choco, orphans, drivers, real installer, arm64 | later |

## Also on the shelf

- Sandbox dev build with the WinUI shell: branch `worktree-agent-a7c285be2b9791f54` (0d9c008, built on m2 at
  7edd549), zip `Purge-sandbox-dev-2.zip` on the Desktop. Not merged; nothing ran inside Sandboxie yet.
- After M1b: M3 (UI + broker), per the user's order.
- Evidence: `E:\purge-build\gate-evidence\` (M2 gate, Clean-Pro, M1a re-run, `m1b-spike`).

## CI

`cargo xtask ci` on `m1b` at 574f3af (all of wave 1 merged): all steps passed, 2026-11-16.
