# M1b handoff (2026-11-16)

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
