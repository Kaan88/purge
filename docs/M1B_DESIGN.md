# M1b design (one page)

Full design: `docs/M1B_DESIGN.json` (contracts, 38 packages, gate). Base commit: 3265797 (branch m2).
Where ENGINE_PLAN and the code differ, the design follows the code; the differences are in `plan_corrections`.

## Scope

- Ownership index, built once per run and shared: MSI component clients (all users and contexts) and MSI table rows
  of every installed product, SharedDLLs, Installer\Folders, Burn dependents.
- Harvest for MSI and Burn: install folder from component key paths (fixes the 7-Zip MSI case), bundle children,
  and the services, tasks and firewall rules that point at the app before it is uninstalled.
- Scanners: COM-CLASS, COM-INTERFACE, COM-SHELLEX, SYS-SERVICE, SYS-TASK, SYS-FIREWALL, SYS-BURNDEPS, FS-PKGCACHE,
  FS-WER, REG-ARP-MSI, REG-SHAREDDLLS, REG-INSTFOLDERS, REG-PRIVACY (MuiCache, UserAssist, PCA, UFH), REG-DIAG
  (Tracing, EventLog); SYS-APPX gets guards only.
- Execute and undo for three new action kinds: delete service, delete task, delete firewall rule (by InstanceID
  only). MSI-registration and COM cleanup use the existing key and value deletes behind narrow guard exemptions.
- Guard and policy additions, rig apps and traps, numeric gate.

Three rules: no scanner reads the registry or disk by itself and there is no new whole-registry or whole-volume walk
(one shared reference walk; budgets per scanner); attribution is by program path or installer record, never by
name; a typed action is bound to the identity digest seen at scan time and has a verified backup, a typed inverse,
fault points and a hive flush before any record that vouches for it.

## Waves (model class: C critical = Fable medium, H high = Opus high, M medium = Opus medium, T trivial = Sonnet)

| Wave | Packages |
|---|---|
| 0 | M1B-S0 (T), M1B-SPIKE (H) |
| 1 | M1B-MODEL (C), M1B-SOURCE (H), M1B-WIN-MSIDB (H), M1B-WIN-SCM (C), M1B-WIN-TASK (C), M1B-WIN-FW (C), M1B-KB (H), M1B-RIG-GUEST (M) |
| 2 | M1B-GUARD (C), M1B-POLICY (C), M1B-SOURCE-IMPL (H), M1B-OWNERSHIP (C), M1B-SYSOBJ (C), M1B-RIGTOOL (H), M1B-X-FOUND (C) |
| 3 | M1B-HARVEST (C), M1B-FRAMEWORK (C, integration), M1B-PLAN (C), M1B-X-SERVICE (C), M1B-X-TASK (C), M1B-X-FIREWALL (C) |
| 4 | M1B-S-COM (C), M1B-S-SHELLEX (C), M1B-S-SERVICE (C), M1B-S-TASK (C), M1B-S-FIREWALL (C), M1B-S-BURN (C), M1B-S-MSIREG (C), M1B-S-PRIVACY (C), M1B-S-DIAG (H), M1B-S-APPX (C), M1B-X-INTEG (C, integration) |
| 5 | M1B-SCAN-INTEG (H, integration) |
| 6 | M1B-RIG-HOST (M), M1B-RIG-EXEC (H) |
| 7 | M1B-GATE (H; Haiku babysits the VM campaign) |

Independent Fable reviews: R1 after wave 1 (contracts, Windows wrappers), R2 after wave 3 (guard, policy, ownership,
harvest, framework, executor modules), R3 after wave 4 (scanners, executor integration), R4 after wave 5
(integration, trap list, truth labels). What each reviewer must attack is in `review_points`.

## Critical path

Scan side (sets the length): M1B-S0 -> M1B-MODEL -> M1B-OWNERSHIP -> M1B-FRAMEWORK -> M1B-S-COM -> M1B-SCAN-INTEG ->
M1B-RIG-HOST -> M1B-GATE.
Executor side: M1B-SPIKE -> M1B-WIN-SCM -> M1B-X-SERVICE -> M1B-X-INTEG -> M1B-RIG-EXEC -> M1B-GATE.

## Gate (details and measurement in `gate_procedure`, `gate_criteria`)

- Clean VM: danger_listed 0; dirty VM: danger_blocking 0; danger_preselected 0; userdata_preselected 0.
- precision_safe 100 %; protected_correct 100 % (new rigtool metric; the Python pair must show the Launcher's 29
  items protected); band mismatches 0.
- 7-Zip MSI: root found from components; `HKU\<sid>\Software\7-Zip` offered (0 of 3 before, at least 1 of 3).
- 26 trap cases on both bases: escapes 0, missed owned objects 0.
- Typed actions: collateral 0; undo exact for every fully reversible item; 6 of 6 act-time traps skipped; 4 of 4
  undo conflicts reported; crash matrix with every fault point reached, 15 of 15 power-off rounds consistent.
- Budgets on the 591-program host: one reference walk per scan; at most +2.5 s warm and +6.5 s cold on scan and on
  harvest.
- M1a replay: every changed row has an allowed reason.

## Open questions (default in brackets)

1. May services, tasks and firewall rules be preselected? [Yes, only when recorded at harvest, program gone, full undo.]
2. Firewall rule cannot be re-created with its old id (spike decides)? [Restore under a new id, marked partial, never preselected.]
3. Services running under a user account with a stored password? [Offer as partial, never preselected.]
4. Rig versions for Temurin and PowerShell? [Temurin 21 LTS JDK x64 MSI; current PowerShell 7 LTS x64 MSI.]
5. Is +2.5 s warm on scan and harvest acceptable? [Yes for M1b.]

## Cut or moved (reasons in `cut_or_move`)

Firewall AppIso rules (cut); AppX all-users removal and deprovisioning (M3/M4); MSI Directory/File table ownership
(M4 if needed); cached installer files (M4); VS Code user-beside-system (M4); removing a service with its
dependents in one run (M3).
