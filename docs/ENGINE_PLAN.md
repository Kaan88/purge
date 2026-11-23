# Purge: Engine and App Architecture and Delivery Plan

Status: **plan v2, 2026-11-11.** This version replaces the 2026-11-11 draft after four reviews (safety, coverage, launch/UI, feasibility). Every critical and major review issue is resolved in the body. Appendix B, the Review log, maps each one to its resolution.

This document replaces the leftover-engine parts of `docs/PARITY.md`. It also covers the program list, safety, UI and AI-agent design. Where it conflicts with `PARITY.md`, this plan wins; the required `PARITY.md` edits are in §11.5.

Inputs:
- `docs/COMPARISON.md`: the 3-way VM test of the clone, UT and BCU.
- `vm/results/*` and `vm/guest/lib.ps1`.
- The BCU 6.3 source (Apache-2.0), read as data.
- The `draft_clone` audit.
- Eight research tracks: BCU junk engine, leftover locations, evidence sources, UI stack, clone reuse, competitors, AI agent, safety and undo.

---

## 0. Decisions at a glance

| # | Decision | Why (short) |
|---|---|---|
| D1 | **Engine in Rust** (`purge-engine.exe`, static CRT, `windows`/`windows-sys`). **UI in C# .NET 10 WinUI 3**, Native AOT. | See the decision record in §3.5. The clone's Rust code is not the reason: almost none of it is reused. |
| D2 | **UI runs `asInvoker`**, plus an on-demand elevated **broker** (same engine exe, `--broker`) | A UAC prompt on every launch would cost more than the whole launch budget. It would also break drag and drop. |
| D3 | **Final consent is shown by the broker** (a high-IL TaskDialog), not by the medium-IL UI | UIPI only protects a higher-IL window. The UI's own "Approve" button can be driven by any same-user process. |
| D4 | **Evidence model with typed tiers and blockers.** No additive name scores. **Value-level and key-level evidence are separate types.** | BCU's integer sums preselected unrelated items. The clone's name matching pre-ticked Windows' Notepad.lnk. |
| D5 | **Pre-uninstall harvest.** Leftovers are proved from what the app registered before its uninstaller ran. | This is the only reliable way to catch VS Code's 135 association skeletons, Git's shell keys and COM after deletion. |
| D6 | **Nothing is deleted outright.** Files are moved to a same-volume quarantine, registry data goes to a lossless JSON backup, and every step is journaled. Every action has a typed inverse. | The BCU console crashed mid-delete with no backup. The clone used `remove_dir_all`. |
| D7 | **AI agent = untrusted advisor.** It can propose and veto. Only the engine can prove, and only the user, in the broker's window, can approve. | The agent extends coverage and safety without becoming a deletion path. |
| D8 | **Engine first, UI second.** The engine is scored as a dry run (plan JSON) in the VM rig before the UI is built. | The WinUI floor is already measured; the engine is the risky part. |

---

## 1. Goals, non-goals, success metrics

### 1.1 Goals

1. **The best leftover cleaner on Windows, measured.** Purge should find more of each app's real leftovers than UT, BCU or any surveyed tool. It must never offer anything that existed before the install, anything another installed product still owns, or the user's own data as preselected.
2. **Attribution from evidence, not names.** Every candidate carries typed evidence. A name match never preselects anything.
3. **Everything is reversible.** Quarantine, lossless registry backup and a journal. Undo is one click, and each action type has its own inverse.
4. **Ready for an AI agent without depending on one.** One JSON API serves the UI, the CLI and a future MCP server. The agent proposes and vetoes; the engine proves; the user approves.
5. **Native Windows 11 look** (WinUI 3, Fluent, Mica). The only performance priority is launch time.

### 1.2 Non-goals

- No generic registry cleaner and no "orphan sweep" that isn't tied to an app. The only exception is the opt-in "System tidy" group (unchecked, never attributed to an app).
- No "aggressive" mode that lowers thresholds. A depth setting may only add scanners.
- No kernel driver. Tracing uses ETW only.
- No UT code, binaries, strings, constants, decompilations or derived rules. This includes the clone's `programs.rs` (§4.2).
- No egui. No Rust WinUI until Windows Reactor reaches 1.0.
- No background service, telemetry, update checker or scheduled task. Purge runs only when opened.
- Purge never writes to Windows-managed opaque stores: StateRepository, AppxAllUserStore, PolicyCache, TaskCache, UserChoice, BAM, the Winsock catalog, the driver store, CBS. It reports them only.
- No x86 build, and no arm64 build until arm64 hardware is in the rig.

### 1.3 Success metrics (VM rig, §10)

**Status (M0 done, 2026-11-11): the 8 apps were re-run under per-app restore and the numbers are frozen in `vm/truth/FROZEN.md`.** Original note: **No per-app number is frozen until M0 has re-run the 8 apps under per-app snapshot restore.** The current truth sets are cross-contaminated: `snap-git-0` already contains VS Code's `.sh` and `.py`, and `snap-python-0` contains Git's `sh_auto_file`. Targets are therefore stated as bands (§1.4).

| Metric | Definition | Gate |
|---|---|---|
| `danger_listed` | Offered items (any band) that are present in the app's clean `snap0`, or owned by a still-installed product. Measured on both the clean VM and the **dirty-baseline VM** (§10.2). | **0** (hard CI fail) |
| `danger_preselected` | Same, for preselected items | **0** |
| `userdata_preselected` | Preselected items labelled UserData by truth, including user files planted after install inside app roots and AppData | **0** |
| `precision_safe` | Safe ∩ truth ÷ Safe. Children of truth items count as hits. | **100 %** |
| `recall_visible` | Truth ∩ (Safe ∪ Likely) ÷ truth. **Macro-averaged per app.** | ≥ 90 % macro, no app < 75 % |
| `recall_safe` | Truth ∩ Safe ÷ truth, macro-averaged per app | ≥ 75 % macro |
| `recall_ext` / `recall_force` | `recall_visible` for the R-ext path (vendor uninstall run outside Purge) and the R-force path (uninstaller broken; truth = snap1 − snap0) | ≥ 70 % / ≥ 60 % macro; danger 0 |
| Per-kind and per-scanner recall | Macro by installer kind (MSI, Inno, NSIS, Burn, Squirrel, MSIX…) and per scanner | Reported; no kind < 60 % at M4 |
| `protected_correct` | Items owned by a remaining product shown as Protected, with a correct related-product suggestion | 100 % |
| `undo_fidelity` | Clean, then undo, then compare against the pre-clean deep snapshot over the fields in §10.3 | 100 % |
| `collateral` | Post-execution diff outside the plan, after removing the ambient set | **0** |
| `guard_escapes` | Trap corpus plus a scripted adversarial agent | **0** |
| `recall_listed` | Truth ∩ any band (Weak included) | Informational only (the Weak band is hidden) |

**Launch metrics.** Dev host, warm, interleaved harness (§9.2):

| Metric | Gate |
|---|---|
| First Rendering tick, full S1 skeleton | ≤ bare-WinUI control + 60 ms p50, measured interleaved in the same run. Absolute guard ≤ 360 ms p50 / 420 ms p90. |
| **Names visible (presented frame with rows)**: primary gate | ≤ 400 ms p50 / 460 ms p90 |
| Icons visible, warm icon cache | ≤ 1 s. A cold cache is reported, not gated. |
| First launch after install or update, Defender real-time on | ≤ 1.2 s p50 (5 fresh copies) |
| Cold after reboot, bare metal (protocol §9.2) | ≤ 1.0 s p50 on the dev host; iGPU laptop reported |
| VM | Functional only (starts on clean Windows with no prerequisites). The WARP render path is reported, not gated. |

**Engine timing:**

| Metric | Gate |
|---|---|
| Harvest complete after the UAC click, typical app (VS Code) | ≤ 2x the bare registry-walk floor of the same machine in the same run, and ≤ 20 s (M3_DESIGN.md 9.1; was ≤ 3 s, DECISIONS 2026-11-23 "G12 harvest row relative to the walk floor") |
| Post-uninstall scan, cold broker, targeted (§5.1) | ≤ 10 s; first progress within 100 ms |

### 1.4 Per-app targets (bands; numbers frozen after the M0 re-run)

| App | Target |
|---|---|
| Firefox (measured both alone and with Thunderbird) | Every truth item visible. **Safe:** install-dir remnants, `Mozilla\Firefox` keys, `FirefoxHTML/URL/PDF-<hash>` ProgIDs, `Clients\StartMenuInternet\Firefox-<hash>`, `AppUserModelId\FirefoxToast-<hash>`, the Default Browser Agent task, Maintenance Service leftovers (co-removed product), `ProgramData\Mozilla-<guid>\updates\<hash>` subfolder, `ShimInclusionList\plugin-container.exe` value. **Likely:** profiles (UserData), the three ISimpleDOM `Interface` keys (shared IIDs). Vendor parents are delete-if-empty only. With Thunderbird present, nothing of Thunderbird's is listed. |
| VS Code (system) | OpenWithProgids **values** Safe. `.ext` / `OpenWithProgids` **skeletons** Safe when a baseline for the matching (edition, build) exists, otherwise X-SYSTIDY (unchecked). PATH segment Safe. Sparse AppX package Likely. `ApplicationAssociationToasts` values Safe. |
| Git | `LibraryFolder\Background\shell` and `sh_auto_file` Safe through `ProvenOwnedSkeleton`, given a matching baseline. PATH Safe. |
| Python 3.12 | 3.12's own items (including `editwithidle` subkeys inside launcher ProgIDs, row granularity) Safe. Launcher-owned items Protected, with "Uninstall Python Launcher too?" shown only if no other Python remains. Package Cache gated on MSI state. |
| 7-Zip | Defender's `{042D2B7D…}` never listed. 7-Zip's own CLSIDs Safe if any are left. |
| Notepad++ | `Notepad.lnk` never listed. `%APPDATA%\Notepad++` Likely (UserData: `backup\` holds unsaved documents). Sparse package Likely if it is still registered. |
| Node.js | User PATH `…\npm` segment Safe (MSI Environment table). No false positives. |
| VC++ redist | No candidates offered at all. |

---

## 2. Lessons from the 3-way test, each mapped to a design decision

| # | Observed | Design decision |
|---|---|---|
| L1 | The clone pre-ticked Windows' `Notepad.lnk` for Notepad++ (`norm` dropped `++`). | Tokens keep symbols (§5.4). Shortcuts are attributed only by their raw target or arguments, never by name. A Windows target is a hard block. A name never preselects. |
| L2 | The clone found 1 of 168 leftovers by name matching under a few roots. | Drop `leftovers.rs`. Use the harvest, the reference index, installer manifests and the evidence graph. |
| L3 | No tool removed VS Code's `.ext` / `OpenWithProgids` keys (Inno `uninsdeletevalue` without `…ifempty`). | Value-level association handler, `ProvenOwnedSkeleton`, and a baseline keyed by (edition, build) (§5.7.1). |
| L4 | Git left the parent `shell` keys and `sh_auto_file`. Its log names only the leaf keys. | `ProvenOwnedSkeleton`: at harvest, every value and subkey in the subtree was attributed to Git; it is empty now; it is not in the baseline. Tier A. |
| L5 | Firefox's leftovers sit under `Mozilla`, `mozilla.org` and `Mozilla-<guid>`. | Vendor aliases, `HarvestedToken` (install hash 308046B0AF4A39CB), knowledge packs anchored to harvested facts, and the vendor-container rule (delete-if-empty only). |
| L6 | BCU-console crashed on nested items and a missing file, with no backup. | Planner collapses nesting. Executor treats "already gone" as success, never aborts the batch, and backs up first. |
| L7 | BCU's COM scanner disabled itself after the uninstall (`IsSystemDirectory` on missing paths). | COM is attributed from the harvest plus checked dangling references. The engine never derives "is system" from a missing path's attributes. |
| L8 | No tool scanned ProgIDs, verbs, App Paths, PATH, sparse MSIX, UserData `S-1-5-18` or UpgradeCodes. | New scanners for all of them, plus a catch-all reference scanner (REF-ANY). |
| L9 | The clone claimed Python 3.12/3.13 shared items and `Microsoft.NET`. | Ownership index over all apps and profiles. Multi-owner items are blocked and re-checked at execution. |
| L10 | Python's `.py*` keys belong to the Python Launcher MSI, which is still installed. | MSI ownership at **Registry-row granularity**. Block when any client other than the target exists. Related-product suggestion. |
| L11 | 7-Zip's "leftover" CLSID is Defender's `SecurityHealthAgent.dll`. | Hard block on reference targets that exist and are Microsoft-signed, in WinSxS or in the baseline. The truth is relabelled to ambient. |
| L12 | The rig hides real leftovers twice: `score.ps1 $Ambient`, and `lib.ps1 $Noise` at capture time. | Capture everything raw; filter only in the scorer with a null-run ambient set. A CI rule ties every scanner to a captured root. |
| L13 | UT: zero danger, low recall. BCU: high recall, low bar, crashed. | Separate ownership and harm axes, hard blockers, and Safe only with Tier A evidence. |
| L14 | Sparse MSIX packages are invisible to UT and the clone. | AppX inventory through `PackageManager`, linked by external location or harvested family only, never by publisher. |
| L15 | Key-level snapshots, footprint 0/0, the VM not reset, contaminated `snap0`. | M0 rig fixes: per-app restore, `snap1`, value-level capture, re-run, and discarding the old `snap0` as baselines. |
| L16 | The clone won't start on clean Windows. | Static CRT engine, self-contained WinAppSDK, AOT. The VM checks start-up on clean Windows. |
| L17 | 77+ verbatim UT strings, plus a `programs.rs` that reconstructs decompiled UT logic. | Nothing from `programs.rs`. The inventory is written fresh from BCU and Microsoft docs. A CI string check runs against UT's `English.xml`. |
| L18 | An elevated tool run as another admin scans the wrong HKCU / AppData. | The interactive user comes from the pipe client (impersonation) and the shell token. The engine never uses HKCU or environment variables for per-user scope. |

---

## 3. System architecture

### 3.1 Process model

| Process | IL | Lifetime | Role |
|---|---|---|---|
| `Purge.exe` (C# WinUI 3, AOT) | Medium (`asInvoker`) | While the window is open | UI only. Never touches the system. |
| `purge-engine.exe --stdio` | Medium | Spawned from the custom `Main` before XAML init. Exits when its job closes. | Inventory, icons, sizes, per-user read scans (shortcut and content parsing for per-user locations), **per-user uninstallers** (run with the user's token), page-cache warm-up. |
| `purge-engine.exe --broker` | High (UAC) | Started when the user clicks Uninstall / Clean / Undo. Exits **right after an execute or undo completes**, or after 10 min idle. | Harvest, machine-scope uninstalls, ownership index, scans, plan, **consent dialog**, execute, undo, quarantine expiry, journal recovery. |
| `purge-engine.exe <verb>` (CLI) | Either | One-shot | Rig and power users (§3.4). Headless `exec` exists only in `rig-exec` builds. |
| `purge-mcp.exe` (M6) | Medium | Started by an MCP client | AI agent server. The executor is not linked in. |
| `purge-trace.exe` (M5) | High | During an uninstall or a traced install | ETW session for the vendor uninstaller's process tree. |

**Elevation mechanics** (in the UI):
- The UI calls `ShellExecuteExW("runas", purge-engine.exe --broker --pipe <name> --parent <pid> --parent-ctime <filetime>)`.
  - It runs on a dedicated STA background thread with `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI`.
  - `hwnd = 0` (no owner window; superseded 2026-11-23, DECISIONS "UAC prompt owner": with the main window as the
    owner the prompt was observed parked on the taskbar on the M3 rig).
- Error 1223 shows an InfoBar ("You cancelled the Windows prompt"; "Not started" when the user chose "Not now" at the explanation); it is not an engine error.
- Elevation is requested **when the user clicks Uninstall, before the S2 confirm dialog**. The broker builds its index while the user reads the dialog.

**Broker hardening:**
- Pipe `\\.\pipe\purge-<random128>`, created by the UI with an SDDL that grants only the interactive user's SID and SYSTEM, plus `PIPE_REJECT_REMOTE_CLIENTS` and `FILE_FLAG_FIRST_PIPE_INSTANCE`.
- The broker checks the client: `GetNamedPipeClientProcessId` must equal `--parent`, `GetProcessTimes` must match `--parent-ctime` (survives PID reuse), and the image path must be `%ProgramFiles%\Purge\Purge.exe`.
- The broker exits when the parent's handle is signalled.

**User identity (L18):**
- The broker calls `ImpersonateNamedPipeClient`, then `OpenThreadToken`, then `RevertToSelf`, which gives it the client token without needing SeDebug.
- From that token: `TokenUser` gives the SID, and `SHGetKnownFolderPath(hToken)` gives the Known Folders.
- Cross-check: the shell owner (`GetShellWindow` → `GetWindowThreadProcessId` → `OpenProcessToken`) must have the same SID. On a mismatch the UI shows a warning; per-user scope always follows the shell owner.
- All per-user work goes through `HKU\<SID>` and those paths.

**"Always start elevated"** (setting): the custom `Main` checks elevation **before any WinAppSDK or XAML call** and re-executes itself with `runas`. When the UI is already elevated, it starts the engine directly in broker mode (no `--stdio`, no second UAC). The interactive user is then taken from the shell-owner token. The setting's text says that drag and drop from Explorer won't work.

**Consent (D3).** `plan.execute`, `undo.run` and `quarantine.purge` take only a `plan_id` (or session id). The broker then shows its own **TaskDialog** (high IL, so UIPI blocks lower-IL input):
- the app name;
- item counts per band and category, and the size;
- a list of every UserData, agent-origin, Reversibility-None, boot-time and over-1-GB item;
- the plan hash;
- a verification checkbox ("I reviewed the items marked ⚠") whenever such items are present.

Only the broker's "Move N items to quarantine" button runs the plan. The UI shows "Confirm in the Purge security prompt".
- **The broker executes only plans it built from its own scans.** The UI sends `plan_id` plus selected candidate ids, never targets.
- **Irreversible verbs** (`quarantine.purge`, a boot-time delete with Reversibility None, SYS-DRIVER) each need a fresh broker prompt naming every item.
- **Honest trust statement** (also in the docs): a same-user process with a shell, including an AI agent with a terminal, *is* the user. The MCP/no-executor split and the broker dialog are defence in depth, not a sandbox for the user's own account.

### 3.2 Repository layout

```
purge/
  Cargo.toml                 # workspace, edition 2024, +crt-static, x86_64 only (arm64 later)
  crates/
    purge-model/             # Target, Scope, AppRef, Evidence, Blocker, Candidate, Plan, Journal, Inverse; serde + schemars
    purge-win/               # feature "read" (default) / "write" (exec only)
                             #   reg: raw RegEnumKeyExW/RegQueryInfoKeyW, explicit view, REG_OPTION_OPEN_LINK walk,
                             #        CurrentControlSet→ControlSet00N, HKU\SID\Software\Classes→HKU\SID_Classes
                             #   fs: FindFirstFileExW LARGE_FETCH (never traverses reparse points), handle ops, FileIdInfo
                             #   token/SID/KnownFolders/ProfileList/offreg (offline hives), msi (msi.dll), appx (WinRT),
                             #   scm, taskschd, firewall (MSFT_NetFirewallRule via WMI), shelllink (Load+SLGP_RAWPATH),
                             #   signer, versioninfo, rm (Restart Manager), sr (srclient), taskdialog (consent)
    purge-source/            # RegistrySource / FileSystemSource traits; Live + Fixture (JSON, offline hive via offreg)
    purge-inventory/         # ARP, MSI, Burn, AppX; quiet-string generators; written fresh (BCU-attributed)
    purge-identity/          # AppIdentity, tokenizer/matcher, vendor aliases, signer/VersionInfo, mega-vendor list
    purge-harvest/           # roots (validate_root), Inno log parser, MSI tables, Burn deps, AppX link, ref snapshot,
                             #   subtree baselines, co-removed products, pre-harvest cache
    purge-index/             # reference index (names+data+multi_sz+binary-utf16), ownership index (+MSI rows),
                             #   baseline filter (edition, build), targeted queries
    purge-scan/              # Scanner trait + catalog (§5.6)
    purge-guard/             # canonicalisation, deny-list, gates; pure
    purge-policy/            # bands, preselection, explanation templates; versioned
    purge-plan/              # nesting collapse (Safe-only absorb), EmptyAfterPlan, ordering, plan hash
    purge-exec/              # executor, quarantine, regbackup, journal, typed inverses, locked files, restore point
    purge-kb/                # static packs + lint (M4); lifecycle states (M6)
    purge-rpc/               # NDJSON JSON-RPC 2.0; capability sets {Read, Propose, Execute}
  bins/
    purge-engine/            # --stdio | --broker | CLI verbs (feature rig-exec for headless exec)
    purge-mcp/               # M6; Read + Propose only; NO purge-exec, NO purge-win/write
    purge-trace/             # M5
  ui/
    Purge.App/               # C# .NET 10, WinUI 3, Native AOT, custom Main
    Purge.Client/            # hand-written JSON-RPC client; DTOs generated by NJsonSchema from schemars output
  kb/                        # packs, generic tokens, mega-vendors, shared-components, shared-iids, deny data, baselines
  tools/xtask/               # gen-dto, ui-strings, check-deps, scanner-coverage, bench-launch
  install/install.ps1        # v1 deploy: Program Files + ProgramData\Purge protected DACL
  vm/                        # rig
  docs/  NOTICE  LICENSE  THIRD_PARTY.md
```

`xtask check-deps` asserts that `cargo tree -p purge-mcp` contains neither `purge-exec` nor `purge-win/write`.

### 3.3 IPC / API: one API, four transports

Newline-delimited JSON-RPC 2.0 (UTF-8). Schemas are generated from `purge-model` by `schemars`, and C# DTOs by **NJsonSchema** (no custom codegen) with System.Text.Json source generation. CI round-trips fixture JSON through both. StreamJsonRpc is not used.

| Transport | Sets | Notes |
|---|---|---|
| stdio ↔ `--stdio` | Read, Propose | Medium IL |
| pipe ↔ `--broker` | Read, Propose, Execute | Execute always ends in the broker's consent dialog |
| CLI | Read, Propose; Execute in `rig-exec` builds only | Release CLI `exec` also opens the consent dialog |
| MCP (`purge-mcp`) | Read, Propose; paths redacted | §8 |

Methods (⇢ = notification):

| Group | Method | Set | Notes |
|---|---|---|---|
| engine | `engine.hello` → `{version, elevated, user_sid, shell_sid, edition, build, baseline_available, policy_version}` | Read | |
| programs | `programs.list` ⇢ `programs.batch` (raw ARP first) ⇢ `programs.patch` (MSI props, Burn links, AppX badges) | Read | Medium engine: `MsiEnumProductsExW(szUserSid=NULL)` |
| | `programs.get`, `programs.icons {ids}` ⇢ `icon.batch {id, w, h, bgra}`, `programs.sizes` ⇢ `size.ready` | Read | Icons are viewport-first |
| | `inventory.changes` → `{disappeared[], appeared[]}` | Read | External-uninstall detector |
| uninstall | `uninstall.prepare {program_ids}` → `{session_id, fingerprint_summary, co_products[], running[], quiet_cmd, signer, warnings[]}` | Execute | Harvest. Per-user entries are routed to the medium engine. |
| | `uninstall.run {session_id, mode}` ⇢ `uninstall.progress`, `uninstall.cancel` | Execute | |
| leftovers | `leftovers.scan {session_id \| program_id \| path \| exe}` ⇢ `scan.progress` → `{scan_id, mode: post_uninstall\|external\|forced}` | Read | `path`/`exe` serve portable apps |
| | `scan.candidates`, `candidate.explain`, `location.inspect`, `references.find`, `guard.explain` | Read | |
| plan | `plan.create {scan_id, selected[]}` → `{plan_id, plan_hash, items[], needs[], backup_bytes, warnings[]}` | Propose | No side effects |
| | `plan.validate`, `plan.execute {plan_id}` ⇢ `exec.progress` | Read / Execute | |
| history | `history.list`, `history.get`, `undo.run {session_id, item_ids?}`, `quarantine.expiring`, `quarantine.purge {ids}`, `journal.pending/resume/rollback` | Read / Execute | |
| agent | `annotate`, `probes.submit`, `signature.propose`, `plan.flag` | Propose | M6 |
| kb | `kb.list`, `kb.lint` | Read | |

### 3.4 CLI contract (rig and power use)

```
purge-engine inventory --json                          > inv.json
purge-engine harvest  <program_id> -o fp.json          # broker-equivalent, needs elevation
purge-engine uninstall <program_id> --quiet [--fp fp.json] -o run.json
                                                       # Job object, waits for tree + Global\_MSIExecute + ARP gone
purge-engine scan --fp fp.json [--mode post|external|forced] -o plan.json
purge-engine scan --path "C:\Tools\procexp" -o plan.json
purge-engine plan show plan.json
purge-engine exec --plan plan.json --confirm <hash>    # rig-exec builds only; release opens consent dialog
purge-engine undo --session <id> [--confirm <hash>]
purge-engine journal recover|resume|rollback
purge-engine kb lint kb/packs/*.json --baselines vm/baselines/
```

### 3.5 Decision record D1: engine language

| | Rust engine (chosen) | C# .NET 10 AOT engine (evaluated) |
|---|---|---|
| BCU ports | Rewritten into the evidence model either way. BCU's containers and confidence model are replaced, and its scanners are re-specified (§5.6), so direct C# reuse would be small. | Closer syntax for ports |
| Elevated broker | Static ~2–4 MB exe, no runtime, no AOT trim warnings around COM interop, predictable memory. `ferrisetw` for ETW. | COM under AOT needs ComWrappers source generation. TraceEvent (ETW) is reflection-heavy. |
| WinRT (PackageManager), MSI, SCM, Task Scheduler, firewall | `windows` crate covers all of them | CsWin32 + CsWinRT cover all of them |
| DTO tax | schemars → NJsonSchema (off-the-shelf); about 25 UI DTOs | Shared assembly, no codegen |
| Toolchains | Two (cargo + dotnet) | One |
| MCP SDK | rmcp | Official C# SDK |

**Choice: Rust.** The deciding factors are the security-critical elevated broker (small attack surface, no runtime, no reflection), ETW in-tree, and a physical language boundary that keeps executor code out of the UI and MCP binaries. The two-toolchain tax is capped by NJsonSchema and a small DTO surface.

**Revisit trigger:** if by the end of M1a the BCU-to-evidence port velocity is clearly the bottleneck (subjective review at the M1a exit), switch the engine to C# AOT with the same API. The JSON contract makes this switch local.

### 3.6 Data flow

```
 Purge.exe (WinUI, medium)
   │ custom Main: CreateProcessW(engine --stdio, pipes, KILL_ON_JOB_CLOSE job) ──► purge-engine --stdio (medium)
   │                                                                                programs.list/patch, icons, sizes,
   │                                                                                inventory.changes, per-user uninstalls,
   │                                                                                page-cache warm-up (background I/O prio)
   │ user clicks Uninstall ─► STA thread ShellExecuteEx runas ─► purge-engine --broker (high)
   │   (S2 confirm dialog shown while broker indexes)               │  pipe: SDDL + PID + ctime + image check
   │                                                                ├─ 1 HARVEST  roots(validate_root), exes, Inno log, MSI
   │                                                                │             tables, Burn children, AppX, ref snapshot,
   │                                                                │             subtree baselines, co-products, tokens
   │                                                                ├─ 2 OBSERVE  vendor uninstaller in Job (+ETW, M5)
   │                                                                ├─ 3 VERIFY-GONE ARP gone? MSI UNKNOWN all ctx? exes gone?
   │                                                                ├─ 4 QUERY    targeted queries from anchors; ownership idx
   │                                                                ├─ 5 SCAN     scanners → Candidates{evidence, blockers}
   │                                                                ├─ 6 DECIDE   guard + policy → bands
   │ S3 review ◄── scan.candidates ─────────────────────────────────┤
   │ user selects → plan.create ───────────────────────────────────►├─ 7 PLAN     collapse, EmptyAfterPlan, order, hash
   │ "Confirm in the Purge security prompt"                         ├─ 8 CONSENT  broker TaskDialog (high IL)
   │                                                                ├─ 9 EXECUTE  validate → backup → act → verify → journal
   │ history/undo ◄─────────────────────────────────────────────────┘    exits after completion
   │                                        C:\ProgramData\Purge\{sessions,Quarantine,fp,kb}  (installer-created, protected DACL)
 purge-mcp.exe (medium, no executor) ── Read/Propose ──► %LOCALAPPDATA%\Purge\agent\ (untrusted; protective rules only)
```

---

## 4. Program inventory

### 4.1 Sources

| Source | API | Notes |
|---|---|---|
| Uninstall keys | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (64 + 32 view). `HKU\<SID>\…\Uninstall` for every loaded profile (interactive user first). **Unloaded profiles:** read-only through offreg on a copy of `NTUSER.DAT`, broker only, used for ownership. | One entry per key; the engine never deduplicates. Each entry is tagged `writable_by: admin \| user`. |
| MSI | Medium: `MsiEnumProductsExW(NULL, NULL, ALL contexts for current user + machine)`. Broker: `szUserSid = "s-1-1-0"`, `MSIINSTALLCONTEXT_ALL` (all users). `MsiGetProductInfoExW` for `InstallLocation`, `LocalPackage`, `InstallDate`. | Merged into ARP by ProductCode, never by name. Sent as `programs.patch`. |
| Burn | ARP `BundleProviderKey/UpgradeCode/CachePath/Tag`; `HK*\SOFTWARE\Classes\Installer\Dependencies\<provider>\Dependents` | Child packages, including `SystemComponent` MSIs, are linked to the bundle. Permanent packages become `related`. |
| AppX / MSIX | `PackageManager.FindPackagesForUser("")` (medium); `FindPackages()` (broker). Properties: `SignatureKind`, `IsFramework`, `IsResourcePackage`, `EffectiveExternalPath`. | A sparse package is linked to a Win32 entry **only** when its external location equals or lies under a validated InstallRoot, or when its family was recorded in a harvest. Never by publisher. The Store tab loads lazily. |
| Updates | `ParentKeyName`, `ReleaseType` | Grouped in the UI |
| Portable / forced | `leftovers.scan {path\|exe}`: identity from VersionInfo plus the signer | |
| v2 | Steam, Scoop, Chocolatey, Windows features | BCU factory ports |

Each entry carries:
- raw flags (`system_component`, `has_display_name`, `has_uninstall_string`, `parent_key`, `release_type`, `windows_installer`);
- `installer_kind`, `scope`, `hive_sid`, `product_code`, `upgrade_code`, `inno_app_id`;
- raw `install_time_evidence[]` (InstallDate, key LastWriteTime, install-dir CreationTime, `unins000.dat` CreationTime, MSI InstallDate).

Tabs are a UI policy over these flags.

### 4.2 What is reused from the clone

**Nothing from `programs.rs`.** It reconstructs UT's decompiled registry reader: the dedup rule, the install-time formula, the `0xC0000000` mask, the "no DisplayName" rule, the MSI UserData merge. Its UT count parity is a product of that copying. `purge-inventory` is written fresh from BCU `RegistryFactory.cs` (attributed) and Microsoft's documented Uninstall-key semantics.

Reused only after rewriting:
- `util.rs` `expand_env`, with the buffer-retry fix;
- `company_name` (VersionInfo CompanyName/ProductName/FileDescription; generic).

Not reused:
- `trace::compare`: the rig scorer is PowerShell, and `lib.ps1` already has `TopMost()`.
- The helper-name list (`wait_for_helpers`). The Job object is the mechanism. A small fallback list of helper names is kept in `kb/uninstaller-helpers.json`, sourced from BCU and public installer docs, not from the clone.

What the clone does give Purge: lessons, the regression cases B1–B19, and the headless-harness pattern.

### 4.3 BCU factories and helpers to port

Every ported file keeps BCU's header line `Copyright (c) 2017 Marcin Szeniak` and adds `Modified by Purge` plus `// Ported from BCU: source/<path> (Apache-2.0)`.

| BCU source | Purge crate |
|---|---|
| `Factory/RegistryFactory.cs`, `ApplicationUninstallerEntry.cs` (trimming, validity as a starting point) | `purge-inventory` |
| `InfoAdders/{Is64BitGetter, InstallDateAdder, AppExecutablesSearcher, FastSizeGenerator}`, uninstaller-kind detection | `purge-inventory`, `purge-harvest` |
| `MsiUninstallStringGenerator`, `NsisQuietUninstallStringGenerator`, `InnoSetupQuietUninstallStringGenerator` | `purge-inventory::quiet` |
| `ProcessStartCommand` | `purge-win::cmdline` |
| `Startup/Normal/StartupEntryFactory.cs`, `NewStartupDisable.cs` | `purge-scan::startup` |

### 4.4 Uninstall runner

**Where it runs:**
- **Per-user entries** (HKU ARP, or an uninstaller path writable by the user) run from the **medium `--stdio` engine** with the user's token. Purge must never become an elevation vehicle for a medium-writable command.
- **Machine-scope entries** run in the broker, only if every ancestor of the uninstaller path is writable by administrators only. Otherwise they run in the medium engine and the vendor uninstaller self-elevates.

**Before running:** S2 shows the exact command and its Authenticode signer.

**Quiet commands:**
- `QuietUninstallString` when present;
- otherwise generated: MSI `msiexec /x {PC} /qn REBOOT=ReallySuppress` (built from the ProductCode; `/I{`→`/X{` handles any spacing), Inno `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, NSIS `/S` with BCU's `_?=` handling.

**Launch and wait:**
- `CreateProcess` inside a Job object (breakaway off).
- Wait for the whole process tree, plus `Global\_MSIExecute`, plus the ARP entry to disappear. NSIS and Inno re-launch from `%TEMP%`, and the job follows them.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | Success *candidate* (see verify-gone) |
| 1605 | Already gone |
| 1641 / 3010 | Success, reboot needed |
| 1602 | Cancelled |
| Other | Failed; offer forced cleanup |

**Verify-gone** (gates the Safe band, §5.8.3): the ARP entry is gone, `MsiQueryProductStateW` is UNKNOWN in **all** contexts, and the main exes in the fingerprint are gone. If not, the scan runs in `forced` mode: no preselection, plus an InfoBar ("The uninstaller finished but <app> still appears installed (repair/modify or cancel?)").

**Running processes** under the roots (Toolhelp32 + `QueryFullProcessImageNameW`): `WM_CLOSE` first, termination only with consent.

---

## 5. The cleaning engine

### 5.1 Pipeline and scan modes

`harvest → observe → verify-gone → query → scan → decide → plan → consent → execute`

| Mode | When | Evidence available |
|---|---|---|
| `post_uninstall` | Purge ran the uninstall | Everything. **Targeted queries** driven by the harvest anchors (reference snapshot keys, ProgID/CLSID/AUMID/token sets, roots), not a global walk. |
| `external` | App disappeared outside Purge (`inventory.changes`) | Pre-harvest cache (§6.2), remembered roots, dangling references, KB, global reference index |
| `forced` | Uninstaller broken, verify-gone failed, or a portable path/exe | Live manifests if still present, references, KB, names. No Safe unless Tier A from a trusted source. |

### 5.2 Entities

```rust
pub enum Target {
    Path { path: CanonPath, kind: FileOrDir },
    RegKey   { hive: Hive /*HKLM|HKU(Sid)|HKU(Sid_Classes)*/, view: View, path: String },
    RegValue { hive: Hive, view: View, path: String, name: RegName },
    RegMultiSzSegment { hive, view, path, name, segment: String, index: u32 },
    Service(String), Task(String), FirewallRule { rule_id: String },
    AppxPackage { full_name: String }, DefenderExclusion { kind, value }, Shortcut(CanonPath),
}
pub enum Scope { Value, Key }            // evidence scope: which target type it may support

pub struct Root { path: CanonPath, kind: RootKind, source: RootSource, trust: SourceTrust }
pub enum RootKind { InstallRoot, ReferencedDataDir, InferredRoot /*DisplayIcon/uninstaller dir*/ }
pub enum SourceTrust { AdminOnly, UserWritable }   // HKU ARP, %LOCALAPPDATA% stores = UserWritable

pub struct Evidence { kind: EvidenceKind, tier: Tier /*A|B|C|Ai*/, weight: i8, scope: Scope,
                      trust: SourceTrust, source: SourceId, detail: Facts }
pub struct Candidate {
    id, target, action, owner: AppRef, origin /*Scanner|Signature|ProbeAgent|ManualUser*/,
    category /*AppFiles|AppData|UserData|Cache|Registration|Association|ShellCom|Startup|System|Privacy|Package*/,
    evidence: Vec<Evidence>, blockers: Vec<Blocker>, harm, reversibility, inverse: InverseKind,
    children: Vec<CandidateId>, fingerprint: ItemFingerprint, size_bytes, child_count,
    decision: Decision, ai: Option<AiAnnotation>,
}
```

**`validate_root(path, source)`.** A root is rejected (it cannot be any root kind) if it is:
- inside or equal to a deny-listed path (§5.10), including `%WINDIR%` and `Common Files`;
- a Known Folder, or inside a user-content Known Folder (Documents, Desktop, Downloads, Pictures, Videos, Music, Saved Games);
- under a sync root;
- a volume root, `Program Files*`, `ProgramData`, the `%LOCALAPPDATA%\Programs` root or a vendor folder holding other apps;
- under `Package Cache`, `Windows\Installer` or `InstallShield Installation Information`;
- the parent of any other app's anchor (UninstallString, DisplayIcon, exe, service ImagePath).

Root kinds:
- **InstallRoot**: only from ARP `InstallLocation`, MSI component paths (Burn: the union over child packages), the Inno `{app}`, or AppX `InstalledLocation`.
- **InferredRoot**: from DisplayIcon or the uninstaller dir. **Tier B only, never quarantined whole.**
- **ReferencedDataDir**: a directory referenced as data, library, output, download or save path. At most `ReferencedByApp` (Tier B), always UserData, never preselected, never a whole-directory target.

**Fingerprint** (per app, persisted in the session journal):
- validated roots, with kind and trust;
- the exe/dll set, plus `AppFileOutsideRoot` anchors (manifest-declared files elsewhere, e.g. `py.exe` in `C:\Windows`, used only for dangling detection);
- identity (§5.4);
- MSI product, upgrade and packed codes, plus **Registry/ProgId/Extension/Class/TypeLib/Environment rows**;
- the Inno log;
- Burn children and dependents;
- AppX full names and families;
- services, tasks, firewall rule IDs and Run entries pointing into roots;
- **harvested tokens** (§5.3);
- the **reference snapshot** (§5.5) with parent-key value and subkey counts;
- **subtree baselines** of harvested keys (value names and hashes, subkeys, LastWriteTime, owner/DACL TrustedInstaller flag);
- **co-removed products** (ARP entries that disappear during the session, with their own pre-harvest fingerprints);
- the time window `[install_time, t_start, t_end]`.

### 5.3 Evidence types and weights

Tier A is explicit: a checked fact from the system or the installer's own record, captured from an **AdminOnly** source when the target is machine-scope. **Rule T:** evidence from a `UserWritable` source never attributes machine-scope targets (HKLM, Program Files, ProgramData outside the user's own vendor folder, services, tasks, firewall). For those it is downgraded to Tier B.

| Kind | Tier | W | Scope | Verified by |
|---|---|---|---|---|
| `InsideInstallRoot` | A | 9 | Path | Under a validated **InstallRoot**. Does not carry over to descendants with their own conflicting evidence (§5.5). |
| `InstallerManifest{inno\|msi_row\|appx\|burn\|vendor_log}` | A | 8 | as recorded | Read **before** the uninstall. Value records → Value scope only. Key-create records (Inno `RegDeleteEntireKey` / `RegDeleteKeyIfEmpty` on that exact key, an MSI Registry row with `+`/`*` key or a ProgId/Class/TypeLib row) → Key scope. |
| `Traced{session}` | A | 10 | as observed | ETW CreateKey Disposition=new or CreateNewFile by the tree (M5) |
| `InPreUninstallRefSnapshot` | A | 8 | Value | The harvest recorded this value referencing a root, exe, ProgID, CLSID, AUMID or token |
| `ProvenOwnedSkeleton` | A | 8 | **Key** | At harvest, every value and subkey in the key's subtree was attributed to the target with Tier A (or the key is an Inno/MSI key-create record). Now value-free. Not in the (edition, build) baseline. No TrustedInstaller owner/ACE. |
| `DanglingRef{root}` | A | 7 | Value | The target returns `ERROR_FILE_NOT_FOUND`/`PATH_NOT_FOUND` on a **mounted fixed NTFS/ReFS volume with the recorded serial**, and its nearest existing ancestor is the root's recorded parent. Unavailable, locked, removable or network paths are never dangling. |
| `PointsIntoInstallRoot` | A | 6 | Value | Data or name resolves into an InstallRoot or the exe set |
| `HarvestedToken` | A | 7 | Path/Key/Value segment | GUID or ≥ 12-hex token taken from the target's own ProgIDs, AUMIDs, ARP key name or anchors (e.g. Firefox `308046B0AF4A39CB`, Inno AppId, MSI codes, electron-builder appId). Whole-segment match. Absent from all other apps' anchors and from the baseline. |
| `AppNamedKeyWithRootRef` | A | 7 | Key | `Software[\WOW6432Node]\<Vendor>\<Product>` or `…\<Product>`, depth ≤ 2: token match plus at least one value into an InstallRoot, no value or subkey referencing another app's anchors, not a structural container, not under `SOFTWARE\Microsoft`, not older than the install |
| `ComKeyOwnership` | A | 7 | Key | CLSID/AppID/TypeLib-version key: harvested server path into an InstallRoot (or a manifest-declared AppFileOutsideRoot), only standard COM subkeys, no other referrer, not in baseline, not in `shared-iids.json` |
| `UninstallerArtifact` | A | 6 | Path/Key | The app's own ARP key or uninstaller file. MSI registration of a product that is UNKNOWN in all contexts. |
| `AppxExternalLocation` | A | 8 | Package | External location equals or lies under an InstallRoot, or the family was harvested |
| `ChainedRef{anchor}` | anchor's tier | 5 | Value or Key per chain | `.ext` default or OpenWithProgids value → owned ProgID; Interface → owned proxy CLSID; Capabilities → owned ProgIDs |
| `RememberedManifest` | A (admin store) / B (user store) | 8 / 4 | as recorded | Pre-harvest cache (§6.2) |
| `KnowledgeRule{shipped, anchored}` | A | 8 | as declared | Shipped pack, VM-validated in CI, match anchored to a harvested Tier A fact from this session (signer + ARP entry) |
| `KnowledgeRule{other}` | B | 4 | as declared | Unanchored match, or a local/agent pack |
| `ReferencedByApp` | B | 4 | Path | A data dir referenced by the app's config. Always UserData. |
| `ContentMentionsAppPath` | B | 4 | Path | Text file ≤ 64 KB in a candidate dir mentions a root or exe (per-user only, parsed in the medium engine) |
| `ProductSubfolderOfVendor` | B | 3 | Path/Key | `<VendorAlias>\<ProductToken>` |
| `ExactFullName` | B | 4 | Path/Key | All tokens with symbols kept, length > 3, directly under AppData/LocalAppData/LocalLow/ProgramData/Software. **Visible as at least Likely.** |
| `NameTokenExact` | C | 3 | Path/Key | §5.4 |
| `VendorContainer` | C | 2 (mega-vendor 0) | Path/Key | Vendor alias name. Only ever **delete-if-empty**. |
| `TimeWindow` | C | 1 | any | Created or LastWriteTime within `[install − 1 d, t_end]` |
| `Ai{model}` | Ai | ≤ +2 / any negative | — | Never counted toward the band (§5.8) |
| Negatives | — | | | `ExecutablesPresent` −4, `ManyFiles` −2, `GenericName` −3, `NameFuzzy` −2, `ModifiedAfterUninstall` −4 |

**Hard blockers** (never selectable; listed under Protected with the reason):

| Blocker | Notes |
|---|---|
| `DenyListed{rule}` | §5.10 |
| `StructuralContainer` | Auto-derived (§5.10) |
| `WindowsBaseline` | (edition, build) filter; children may still go |
| `OwnedByInstalledMsi{product, row}` | **MSI Registry/File/ProgId/Class row granularity** (key + value name). Rows owned by the target stay offerable. Any component client other than the target blocks (`MsiEnumClientsExW`, all users and contexts). |
| `ReferencedByOtherApp{app}` | |
| `InsideOtherApp` / `ContainsOtherApp` | Separator-aware, both directions; includes unloaded profiles' entries |
| `SharedRefcount` | |
| `MsiProductStillRegistered` | Any context |
| `BurnDependentsRemain` | |
| `ExistedBeforeInstall` | |
| `TrustedInstallerOwned` / TI ACE on the key | |
| `MicrosoftSystemTarget` | A referenced or target file **exists** and is Microsoft-signed, in WinSxS or in the baseline, regardless of root. Files under `%WINDIR%` are never deletable (report-only), but dangling registry references to harvested-exe-set files under `%WINDIR%` stay offerable. |
| `SharedIid` | `kb/shared-iids.json`: ISimpleDOM*, IAccessible2*, standard marshalers `{00020424…}`, `{00020420…}` |
| `SyncRoot` | Subtree |
| `HardLinkOutsidePlan` | |
| `RegLink` | After canonicalisation |
| `ReparseMismatch` | Final path ≠ lexical path |
| `WindowsManagedOpaque` | |
| `CannotBackUp` | Shown as report-only |
| `NotGone` | Verify-gone failed, for Safe-only evidence paths |

**Soft blockers** (offered, unchecked): `UnmatchedChildren{n}`, `UserData`, `TooLarge` (> 2 GB or > 50k files), `OlderThanInstall`, `MultiTargetOwner` (deferred, §5.8.4), `ReversibilityNone`, `InUse`, `MsiPackageUnreadable` (an installed product's LocalPackage cannot be read, and its tokens or anchors match the candidate), `ChangedSinceScan` (at execution: skip).

### 5.4 App identity resolution (`purge-identity`)

**Names:** DisplayName, MSI ProductName, Inno AppId/AppName, the NSIS key, the ARP key name, main exe names, VersionInfo ProductName/FileDescription.

**Vendors:** Publisher, Authenticode signer CN (`CryptQueryObject` → `CMSG_SIGNER_INFO_PARAM` → `CertGetNameStringW`, no revocation), VersionInfo CompanyName, the URLInfoAbout/HelpLink host, and KB aliases.

**Anchors:**
- roots and exe set;
- ProgID set **P**: a Classes key whose `shell\*\command` targets the roots **and** that no key outside the app references; DefaultIcon or AUMID alone is not enough;
- CLSID/AppID/TypeLib set, AUMIDs, package families, services, tasks, firewall rule IDs;
- harvested tokens.

**Pre-existing ProgIDs** that the app modified (e.g. `txtfile`) are not in P. They produce value-level **restore** candidates, never key deletes.

**Tokenizer:**
1. NFKC, casefold. Split on whitespace and on `_ - .` between alphanumerics.
2. Keep symbol tokens: `notepad++`, `c#`, `f#`, `.net`.
3. Drop stopwords: versions, `x64 x86 (64-bit) setup edition inc corp corporation ltd llc gmbh foundation the for windows`.
4. Drop generic tokens listed in `kb/generic-tokens.json` (update, updater, helper, launcher, service, data, config, common, bin, app, setup, install, tools, plugins…).
5. IDF: drop tokens that appear in more than 2 installed apps' names, publishers or key names.
6. **If fewer than 1 distinctive token remains (fewer than 2 for mega-vendor publishers), `NameTokenExact`, `ExactFullName` and `ProductSubfolderOfVendor` are disabled for that app.** Unit test: every VC++ redistributable installed together.
7. A match needs every remaining significant token as whole tokens.
8. Names of 3 characters or fewer (`Git`, `Code`) only as an exact full name, and only next to Tier A/B evidence.
9. Sift4 only as a tie-break.

**Mega-vendors** (`kb/mega-vendors.json`): a vendor-only match weighs 0.

### 5.5 Reference index and shared-ownership checks (`purge-index`)

**Reference index:**
- Covers value **names**, REG_SZ/EXPAND_SZ data, **every REG_MULTI_SZ segment**, and UTF-16 strings inside REG_BINARY (bounded to 4 KB per value).
- Scope: `HKLM\SOFTWARE[\WOW6432Node]`, `HKU\<SID>\Software`, `HKU\<SID>_Classes`, `HKLM\SYSTEM\ControlSet00N\Services`, and the Session Manager/Environment keys.
- Matching: case-insensitive, separator-aware, environment variables expanded for the interactive user.
- Golden tests: Firefox `TaskBarIDs` and `Launcher` value names, VS Code empty-data OpenWithProgids names, MuiCache.
- `post_uninstall` mode queries only the harvested anchors. The full index is built only for `external` and `forced` modes.

**Ownership index:**
- Built by the **broker** at start, overlapping the S2 dialog.
- The medium engine only pre-reads the same keys and LocalPackage files at background I/O priority, after icons are done, to warm the OS page cache. The broker never trusts data computed at medium IL.
- Covers all other entries, including the target's siblings and every profile (loaded through `HKU`; unloaded read-only through offreg).

| Input | Detail |
|---|---|
| Roots, exes | Both directions, separator-aware |
| Classes anchors | ProgIDs, CLSID server paths, AUMIDs, families |
| System objects | Service ImagePath/ServiceDll, task actions, firewall `App=` |
| MSI rows | Every installed product's LocalPackage, read-only (`MsiOpenDatabaseW(MSIDBOPEN_READONLY)`): `Component, File, Directory, Registry, RemoveRegistry, ProgId, Extension, Verb, Class, TypeLib, AppId, MIME, Shortcut, ServiceInstall, Environment, Font, CustomAction`. Builds `(target, value name) → {product, component}`. Cached by LocalPackage mtime in `ProgramData\Purge\fp`. Missing LocalPackage → `MsiPackageUnreadable` soft blocker. |
| Refcounts | `MsiEnumClientsExW` (all users/contexts), `SharedDLLs` (both views), `Installer\Folders` |
| Burn | `Installer\Dependencies\*\Dependents` |

**Carry-over rule:** evidence on a directory or key never extends to descendants that are not themselves attributed. The only exception is everything under a validated, manifest-backed InstallRoot that passes verify-gone.

### 5.6 Scanner catalog (`purge-scan`)

`trait Scanner { fn id(&self) -> &'static str; fn captured_roots(&self) -> &[RootSpec]; fn scan(&self, ctx: &ScanCtx, app: &AppIdentity) -> Vec<Candidate>; }`

`xtask scanner-coverage` fails CI if any scanner's `captured_roots` is not captured by the rig. **A scanner without rig coverage cannot emit Safe.**

Phase key:
- **M1a / M1b**: engine core.
- **M4**: coverage expansion.
- **v2**: later.

#### Files and folders

| ID | Locations | Attribution | Default | Action | Phase · origin |
|---|---|---|---|---|---|
| FS-INSTALLDIR | Validated InstallRoot | `InsideInstallRoot` + verify-gone. Blocked if any running process, other ARP UninstallString/DisplayIcon, service or task points inside, or any file was modified after `t_end`. | Safe | quarantine dir | M1a · BCU InstallLocationScanner, rewritten |
| FS-UNINSTALLER | Uninstaller dir/exe, MSI `*{PC}*`, `InstallShield Installation Information\{PC}` | `UninstallerArtifact` | Safe | quarantine | M1a · BCU |
| FS-APPDATA | `%APPDATA%`, `%LOCALAPPDATA%`, LocalLow, `%PROGRAMDATA%`, VirtualStore, depth ≤ 2, interactive user | References, manifest, tokens, KB, `ExactFullName` | Caches (`Cache`, `GPUCache`, `Code Cache`, `CachedData`, `logs`, `crashpad`) Safe with Tier A. **Unknown folders default to UserData.** | quarantine | M1a · BCU CommonDrive, rewritten |
| FS-VENDORPARENT | `Roaming\<Vendor>`, `Program Files\<Vendor>`, Start Menu vendor folders | `EmptyAfterPlan`; a folder holding only `desktop.ini`/`Thumbs.db` counts as empty | Safe when empty-after-plan | non-recursive `RemoveDirectory` | M1a |
| FS-SHORTCUTS | Start Menu (user + common), Desktop (user + Public), Quick Launch, `User Pinned\TaskBar`, `ImplicitAppShortcuts`, Startup folders, `.url`, `.appref-ms` | `IPersistFile::Load` + `GetPath(SLGP_RAWPATH)` + `GetArguments` + AUMID property. **Never `Resolve`.** Parses `--processStart` / `shell:AppsFolder\<AUMID>`. Per-user locations are parsed in the medium engine; admin-only locations in the broker. | Safe | quarantine | M1a |
| FS-DANGLINGLINKS | Symlinks/junctions in PATH dirs, `WinGet\Links` | Reparse target into a former root | Safe | delete link only | M4 |
| FS-DOTFILES | `%USERPROFILE%\.<app>` folders and depth-1 dotfiles (`.python_history`, `.node_repl_history`, `.lesshst`, `.viminfo`) | KB rule or exe-set name; **never the hard-blocked secrets (§5.10)** | UserData, unchecked | quarantine | M4 |
| FS-PKGCACHE | `%ProgramData%\Package Cache\{PC}v*`, `{BundleId}`, per-user `%LOCALAPPDATA%\Package Cache\…` | Harvested provider or product code | Safe only when UNKNOWN in all contexts and no dependents | quarantine | M1b |
| FS-WER | WER `AppCrash_*`/`AppHang_*` via `Report.wer AppPath=`, `CrashDumps`, `LocalDumps\<exe>` | Exe set, unique names | Safe | quarantine | M1b · BCU WerScanner, fixed |
| FS-PREFETCH | `Prefetch\<EXE>-*.pf` | Unique exe name | Safe | quarantine | M4 · BCU |
| FS-TEMP | Installer scratch in `%TEMP%` | Pattern + window + not locked | Unchecked | quarantine | M4 |
| FS-INSTALLERICONS | `Windows\Installer\{PC}\` | Product unregistered | Report-only (`%WINDIR%`) | — | M4 |
| FS-FONTS | Fonts | Manifest/trace | Report or unchecked | `RemoveFontResourceEx` | v2 |
| FS-JUMPLISTS | `AutomaticDestinations` | AUMID hash | Unchecked | quarantine | v2 |

#### Registry: application keys

| ID | Locations | Attribution | Default | Action | Phase |
|---|---|---|---|---|---|
| REG-SOFTWARE | `Software[\WOW6432Node]\<Vendor>\<Product>` (HKLM, HKU), VirtualStore | **Key:** `AppNamedKeyWithRootRef`, manifest key-create, `ProvenOwnedSkeleton`, `HarvestedToken`. **Value:** `PointsIntoInstallRoot` (BCU value-name list plus the reference index). Under `SOFTWARE\Microsoft`, key deletes need InstallerManifest, Traced or ProvenOwnedSkeleton. | Safe with key-level Tier A | key/value | M1a · BCU SoftwareRegKeyScanner |
| REG-ARP-MSI | Own ARP key; `Classes\Installer\{Products,Features,Patches}`; `UserData\{S-1-5-18,<SID>}\Products`; `UpgradeCodes` (our value); `Components\*` **values** with our packed code | `UninstallerArtifact`; UNKNOWN in all contexts | Safe | value/key | M1b · BCU fixed |
| REG-APPPATHS | `App Paths\<exe>`, `Classes\Applications\<exe>` | Into roots or dangling; exe unclaimed | Safe | key | M1a |
| REG-RUN | `Run`/`RunOnce` (64/32, HKU) + `StartupApproved\{Run,Run32,StartupFolder}` value of the same name | Command into roots or dangling | Safe | **value** | M1a |
| REG-ENV | `HKLM\SYSTEM\ControlSet00N\Control\Session Manager\Environment`, `HKU\<SID>\Environment` | Segment under a root **or declared by MSI `Environment` / Inno log / RememberedManifest**; unexpanded text compared; dir gone (checked expanded for the user) | Safe (diff shown) | MultiSz segment edit, `WM_SETTINGCHANGE` | M1a |
| REG-SHAREDDLLS | `SharedDLLs` (both views) | Under a root and the file is missing | Safe | value | M1b |
| REG-INSTFOLDERS | `Installer\Folders` | Under a root, no other product | Safe | value | M1b · BCU |
| REG-PRIVACY | AppCompat `Layers` / `Compatibility Assistant\Store`; UserAssist (all GUIDs); **MuiCache**; FeatureUsage; `Search\JumplistData` | Path/exe/AUMID | Safe, "Privacy traces" group | value | M1b (AppCompat, UserAssist, MuiCache) · M4 (FeatureUsage) |
| REG-DIAG | `Tracing\<exe>_*`, `Services\EventLog\*\<Source>` (expanded, `;`-split), `WINEVT\Publishers`, HeapLeakDetection, Audio PolicyConfig | Exe set / message file | Safe | key | M1b (Tracing, EventLog) · M4 (rest) |
| REG-EXEKEYED | `MediaPlayer\ShimInclusionList\<exe>`, `Internet Explorer\Main\FeatureControl\FEATURE_*\<exe>`, `Low Rights\ElevationPolicy\{GUID}` (AppPath), `DragDrop\{GUID}`, `GameConfigStore\Children` (MatchedExeFullPath), `DirectInput\<EXE>*` | Unique exe name in the exe set, or path into roots | Safe for values; key only when all of its content is covered | value/key | M4 |
| REG-NOTIFY | `Notifications\Settings\<AUMID>`, `PushNotifications\Backup\<AUMID>` | AUMID; package gone | Safe | key | M4 |
| REG-ACTIVESETUP, REG-NMH, REG-OFFICEADDIN, REG-BROWSEREXT | Active Setup, NativeMessagingHosts (never Defender's host), Office `Addins\<ProgID>`, browser `Extensions\<id>` | Path into roots | Safe | key | M4 |
| REG-IFEO | IFEO / SilentProcessExit | Debugger into roots | Report | — | v2 |
| **REF-ANY** | Any value in the reference-index scope whose name or data references a harvested anchor | Value-level only (Tier A if harvested or dangling). The key goes only when every value and subkey is covered (re-checked live). | Safe values | value | M1a |

#### Classes: associations, shell, protocols

Physical hives only: `HKLM\SOFTWARE\Classes` and `HKU\<SID>_Classes`. Never `HKCR`.

| ID | Locations | Attribution | Default | Action | Phase |
|---|---|---|---|---|---|
| CLS-PROGID | `Classes\<ProgID>` in P; `*_auto_file` only through `ProvenOwnedSkeleton` or a command path | Harvest, MSI ProgId row, dangling command | Safe (keys only with a matching baseline) | key | M1a |
| CLS-ASSOC | `.ext` default, `OpenWithProgids` values, `OpenWithList\<exe>`, `SystemFileAssociations`, skeletons | §5.7.1 | Safe values; skeletons Safe only with a matching baseline | value → delete-if-empty | M1a |
| CLS-FILEEXTS | `HKU\<SID>\…\Explorer\FileExts\.ext\{OpenWithProgids,OpenWithList+MRUList}`; UserChoice report-only | Values in P | Safe | value edit | M1a |
| CLS-TOASTS | `HKU\<SID>\…\ApplicationAssociationToasts` values `<ProgID>_<.ext>` | ProgID in P | Safe | value | M1a |
| CLS-AUMID | `Classes\AppUserModelId\<AUMID>` | AUMID in the anchor set | Safe | key | M1a |
| CLS-VERBS | `{*,AllFilesystemObjects,Folder,Directory,Directory\Background,Drive,DesktopBackground,LibraryFolder\Background}\shell\<verb>`; parent `shell` via `ProvenOwnedSkeleton` | Command into roots or dangling | Safe | key | M1a |
| CLS-PROTOCOL | `Classes\<scheme>` with `URL Protocol` | Command into roots | Safe | key | M1a |
| CLS-REGAPPS | `RegisteredApplications`, `Capabilities`, `Clients\StartMenuInternet\<n>`, `Clients\Mail\<n>` | P / command / token | Safe | value + key | M1a · BCU |
| CLS-AUTOPLAY | `Explorer\AutoplayHandlers\Handlers\<n>`, `EventHandlers\*` values | Handler ProgID/CLSID in anchors | Safe | key/value | M4 |

#### COM and shell extensions

| ID | Locations | Attribution | Default | Action | Phase |
|---|---|---|---|---|---|
| COM-CLASS | `Classes[\WOW6432Node]\CLSID\{x}` (HKLM + HKU): InprocServer32, LocalServer32, InprocHandler32, .NET CodeBase, DllSurrogate; AppID; `TypeLib\{x}\<ver>\<lcid>` (all versions and LCIDs) | `ComKeyOwnership` / manifest | Safe | key per view | M1b |
| COM-INTERFACE | `Interface\{IID}` whose proxy CLSID or TypeLib is owned and removed in the same plan | `SharedIid` hard block; otherwise **Likely** unless the IID is declared in the app's own MSI/manifest/typelib and in no other installed app's typelib | Likely | key | M1b |
| COM-SHELLEX | `…\shellex\{ContextMenu,DragDrop,PropertySheet,CopyHook}Handlers\<n>`, DropHandler, IconHandler, DataHandler, thumbnail/infotip/PropertyHandler, `.ext\PersistentHandler`; `Shell Extensions\Approved`, `Cached`; `ShellIconOverlayIdentifiers`; `PreviewHandlers`; `PropertySystem\PropertyHandlers`; `NameSpace`; `SyncRootManager` | CLSID in the app's set | Safe with Tier A; "Restart Explorer" offered | key/value | M1b (handlers, Approved, overlays, preview) · M4 (rest) |
| COM-MEDIA | DirectShow/MF category `CLSID\{cat}\Instance\{x}`, `MediaFoundation\Transforms` | CLSID in the app's set | Safe | key | M4 |
| COM-PACKAGED | `PackagedCom`, `Extensions\ContractId` | — | Hard-blocked | — | — |

#### System integrations (API-only actions)

| ID | Object | Attribution | Default | Action | Phase |
|---|---|---|---|---|---|
| SYS-SERVICE | Win32 services | ImagePath/ServiceDll into roots or dangling; MSI ServiceInstall | Safe only with Tier A and no dependents | SCM stop → `DeleteService` | M1b |
| SYS-TASK | Scheduled tasks | `IExecAction` into roots/dangling | Safe with Tier A | `ITaskFolder::DeleteTask` | M1b |
| SYS-FIREWALL | Firewall rules, including AppIso | `App=`/`Svc=` into a validated root (re-checked) | Safe | **delete by unique rule ID** through `ROOT\StandardCimv2:MSFT_NetFirewallRule` (InstanceID = FirewallRules value name). Never GPO/MDM stores. | M1b |
| SYS-APPX | Sparse/external packages | `AppxExternalLocation`. Never framework, resource, Store-signed, System-signed, or packages with dependents. | **Likely** (Reversibility None) | `RemovePackageAsync` (RemoveForAllUsers only for per-machine Win32 apps). Deprovision only if provisioned within the app's install window. | M1b |
| SYS-BURNDEPS | `Installer\Dependencies\<provider>[\Dependents\<bundle>]` | Our dependent entry; the provider only when unregistered | Safe | key/value | M1b |
| SYS-DEFENDER | Defender exclusions | Path/process in roots; policy-managed → report | Safe | `MSFT_MpPreference.Remove` | M4 |
| SYS-NETWORK | `NetworkList\Profiles`, `Signatures`, NRPT `DnsPolicyConfig`, adapter Class keys | Report-only in v1 | Report | — | M4 |
| SYS-DRIVER | Drivers, Upper/LowerFilters | Report; coupled removal with explicit consent | Report | SCM + our segment + reboot | v2 |
| SYS-CERT | Cert stores | Report | Report | — | v2 |

#### Other

| ID | Scope | Phase |
|---|---|---|
| X-KB | Knowledge-pack matcher (§5.9) | M4 |
| X-SQUIRREL | `%LOCALAPPDATA%\<App>\Update.exe`, `packages\`, `SquirrelSetup.log`; electron-builder `<name>-updater`, `HKU\…\Software\<appId GUID>` | M4 |
| X-CLICKONCE | `Apps\2.0`, `Deployment\SideBySide`: WindowsManagedOpaque, report-only, offer `dfshim` maintenance | M4 |
| X-SYSTIDY | Unattributed empty skeletons, opt-in group, unchecked | M4 |
| X-STORES, X-PFORPHANS | Steam/Scoop/Choco extras, Program Files orphans | v2 |

### 5.7 Special handlers

#### 5.7.1 File associations (value-level)

1. **Harvest.**
   - P as defined in §5.4.
   - For every `.ext` in the app's scope hive, a `JournalEntry` records: OpenWithProgids values (ours / others), subkey count, ext default, other values and subkeys, owner/DACL TrustedInstaller flags, and any vendor backup value (e.g. `Notepad++_backup`).
   - Also recorded: `FileExts` entries, `ApplicationAssociationToasts` values, and the previous ext defaults.
2. **After the uninstall:**
   - Delete values named **exactly** in P.
   - Delete `OpenWithProgids` when it is now empty **and** the journal shows only our value **and** a baseline for this (edition, build) exists that doesn't contain it (`ProvenOwnedSkeleton`).
   - Delete `.ext` under the same conditions applied to its whole subtree.
   - An `.ext` default equal to a removed ProgID is restored from the vendor backup value or the baseline value. If neither exists, it is report-only ("<.ext> has no default app; choose one in Settings").
   - Keys with a TrustedInstaller owner or ACE are never deleted.
3. **No baseline for the running build** (e.g. the host's 26300 Insider build until the M0 Pro VM baseline exists): values only. The skeletons go to X-SYSTIDY (unchecked).
4. **UI:** one group node, "File associations (135 extensions)". One `SHChangeNotify(SHCNE_ASSOCCHANGED)` at the end.
5. **External mode:** RememberedManifest (§6.2) supplies the P set and the ext map. Without it, use dangling ProgIDs, KB packs (winget `FileExtensions`) and X-SYSTIDY.

#### 5.7.2 Other handlers

- **COM:** chain order is shellex handler → Approved → CLSID per view → ProgID → AppID → TypeLib version → Interface, all in one plan.
- **Services:** stop, delete, remove only our filter segment. Backup is `QueryServiceConfig[2]W` + SDDL + key JSON. Undo refuses an ImagePath outside the recorded root.
- **Tasks:** XML backup via `get_Xml`. A task with a stored password is `Partial`.
- **Firewall:** full `MSFT_NetFirewallRule` instance to JSON. Delete and restore by InstanceID.
- **AppX:** API only. Windows-managed residue (StateRepository etc.) is reported as "cleaned by Windows".
- **Burn:** Package Cache + our `Dependents` entry, gated on all-context MSI state.
- **Related-product suggestion** (e.g. Python Launcher, Mozilla Maintenance Service): shown only when the Burn Dependents and the ownership index show **no other remaining dependent** (e.g. no Python 3.13, no Thunderbird).
- **Mozilla specifics (KB):**
  - in `ProgramData\Mozilla-<guid>`, only the `updates\<hash>` / `UpdateLock-<hash>` items matching the harvested install hash are attributed;
  - `profiles.ini` and `installs.ini` are kept whenever any profile directory stays.

### 5.8 Policy, bands and explanation (`purge-policy`, versioned, pure)

#### 5.8.1 Score

`S = Σ over distinct non-Ai evidence kinds of max(weight)`, plus +1 per additional independent source of the same kind (at most +2), plus the negatives. **Ai evidence is excluded from S.** It can only lower the band (a negative Ai weight or a flag moves the item down one band).

Mapping of BCU records:

| BCU record | Purge kind |
|---|---|
| ExplicitConnection | PointsIntoInstallRoot / InsideInstallRoot |
| DirectoryStillUsed | `ContainsOtherApp` |
| ProductNamePerfectMatch | NameTokenExact |
| (others) | Listed in `purge-policy/src/bcu_map.rs` |

#### 5.8.2 Bands

| Band | Rule | UI |
|---|---|---|
| **Blocked** | Any hard blocker | Protected list, read-only |
| **Safe** | Tier A present, with **Scope matching the target type**, Rule T satisfied, S ≥ 8, no soft blocker, harm ≤ Low, category ∉ {UserData, System, Security}, verify-gone passed (or mode ≠ forced) | Checked |
| **Likely** | Tier A with a soft blocker or harm ≥ Medium; or S ≥ 4; or `ExactFullName` | Visible, unchecked |
| **Weak** | S < 4 | Hidden behind "Show weak matches" |

Caps:
- `origin = probe:agent` without engine Tier A → at most Likely.
- `origin = signature`, not shipped or not anchored → at most Likely.
- Any item an agent proposed or touched in a plan starts unticked.

#### 5.8.3 Mode rules

- `forced` mode, or verify-gone failed: nothing is preselected; Safe is shown as Likely, with an InfoBar.
- `external` mode: Safe is possible only from AdminOnly-trusted evidence (RememberedManifest in the admin store, DanglingRef with the recorded serial, shipped anchored KB).

#### 5.8.4 Batches

`MultiTargetOwner` items are deferred until every co-owner's ARP and MSI registration is confirmed gone. If a co-owner remains, the item is re-evaluated as `ReferencedByOtherApp`.

#### 5.8.5 Harm

| Harm | Examples |
|---|---|
| None | Empty key or dir |
| Low | Cache, log, registration, privacy trace |
| Medium | Config, PATH edit |
| High | User data (profiles, documents, saves, DBs, unknown AppData folders) |
| Critical | Drivers, filters, certificates |

#### 5.8.6 Explanation

Fixed templates rendered from evidence, never free text. Examples:
- "Named in Git's uninstall log · now empty · not on clean Windows 11 Pro 26300"
- "Pointed to C:\Program Files\Microsoft VS Code\Code.exe before uninstall"
- Blocked: "Kept: still used by Mozilla Thunderbird"

AI notes are collapsed, badged, and never shown on Likely or UserData rows.

### 5.9 Knowledge packs (`kb/`, `purge-kb`)

**DSL** (declarative JSON):
- `match` (ARP regex, publisher, signer, installer kind);
- `vendor_aliases`;
- `leftovers` (templates with tokens `{guid} {sid} {ver} {install_hash}` and whitelisted location tokens; at most one wildcard segment, at depth ≥ 2);
- `parent_if_empty`;
- `protect`;
- `user_data` (known user-data folders: `Notepad++\backup`, `Code\User`, Firefox `Profiles`);
- `file_assoc {progid_prefix}`;
- `max_weight`.

Lint rejects anything that resolves into a deny-list rule or a secrets store.

**Load locations:**
- *Raising* rules (leftovers, vendor_aliases, file_assoc) load only from the install dir (shipped) or `ProgramData\Purge\kb` (broker-written after approval).
- *Protective* rules (`protect`, `user_data`, "Exclude always") may also load from `%LOCALAPPDATA%\Purge`, because they can only lower confidence.

**M4 (static):**
- Shipped packs are code-reviewed JSON. CI runs lint, a conflict check against the (edition, build) baselines and other apps' Tier A footprints, and a VM validation run.
- **Shipped packs are active by default** (the release pipeline is the approval).
- First packs: Mozilla (Firefox / Thunderbird / Maintenance Service), VS Code (+ Insiders), Git, Python (+ Launcher relation), WinMerge (`Thingamahoochie`), Notepad++, 7-Zip.

**M6 (agent):** the lifecycle `proposed → linted → baseline_clean → vm_validated → approved → active` for local and agent packs, restore-as-negative-feedback, and the S6 approval UI.

**Seed sources (licence-clean):**
- our VM truth runs;
- winget-pkgs (MIT);
- Scoop Main (Unlicense);
- the `chocolatey-community/chocolatey-packages` repository only (Apache-2.0);
- BCU deny data (Apache-2.0).

Winapp2 (CC BY-SA) and BleachBit (GPL) are reference only. Packs ship as a static snapshot per release; there is no network fetch.

### 5.10 Hard deny-list (`purge-guard`)

**Canonicalisation (G1):**
- Whitelisted environment tokens only. `\\?\` form. Resolve 8.3 names.
- Reject `..`, `GLOBALROOT`, UNC, ADS `:`, device names.
- Explicit WOW64 views. HKCR is rejected.
- **`HKLM\SYSTEM\CurrentControlSet` → `ControlSet00N`** (from `HKLM\SYSTEM\Select\Current`). **`HKU\<SID>\Software\Classes` → `HKU\<SID>_Classes`.** These are the only links resolved; any other `REG_LINK` → `RegLink` block.
- Filesystem: the index never traverses reparse points, junctions, symlinks or mount points, and records the tag. Each candidate is opened with `FILE_FLAG_OPEN_REPARSE_POINT`. `GetFinalPathNameByHandleW` must equal the lexical path (else `ReparseMismatch`), and `FileIdInfo` must equal the scan. The deny-list runs on both the lexical and the final path. All prefix tests are separator-aware.

**Rule annotations:** **[S]** whole subtree · **[E]** exact path only · **[E+A]** exact and every ancestor.

**Filesystem:**
- [S] `%WINDIR%` (System32, SysWOW64, WinSxS, drivers, Fonts, Installer, servicing, assembly). One
  exception: single `%WINDIR%\Prefetch\<EXE>-<hash>.pf` files offered by FS-PREFETCH (never the folder)
- [S] `Common Files\Microsoft Shared`, `ClickToRun`, `InstallShield` engine dirs
- [S] `ProgramData\Microsoft` (except Start Menu `.lnk` files with Tier A)
- [S] `WindowsApps`, `%LOCALAPPDATA%\Packages`, `%LOCALAPPDATA%\Microsoft\WindowsApps`
- [S] `Reference Assemblies`, `dotnet`, `Microsoft.NET`
- [S] **Secrets:** `%APPDATA%\Microsoft\{Protect,Credentials,Crypto,SystemCertificates,Vault}`, `%LOCALAPPDATA%\Microsoft\{Credentials,Vault}`
- [S] **Dotfiles:** `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.netrc` (KB rules may name `.config\<app>`, never these)
- [S] **Every sync root subtree** (`SyncRootManager`, `StorageProviderSyncRootManager`) and placeholders (`RECALL_ON_*`, cloud reparse tags)
- [S] `System Volume Information`, `$Recycle.Bin`, `Recovery`, `Boot`
- [S] Purge's install dir, `ProgramData\Purge`, `X:\.purge-q`
- [E+A] drive roots, `Program Files*`, `ProgramData`, `Common Files`, Package Cache (machine **and** per-user), `%LOCALAPPDATA%\Programs`, `steamapps`, Java roots, every KNOWNFOLDERID of every profile, profile roots
- [E+A] every other app's roots (dynamic); [S] their contents

**Registry**: structural, [E+A] unless noted:
- Hive roots; `SOFTWARE`; `WOW6432Node`; `SOFTWARE\Microsoft\Windows\CurrentVersion`; `Windows NT\CurrentVersion`.
- [S] `Policies` under HKLM, HKU, CurrentVersion and Windows NT.
- `Classes` and its `CLSID`, `Interface`, `TypeLib`, `AppID`, `*`, `AllFilesystemObjects`, `Folder`, `Directory[\Background]`, `Drive`, `DesktopBackground`, `LibraryFolder`, `SystemFileAssociations`, `Applications`, `AppUserModelId`, and their `shell`/`shellex` roots (unless `ProvenOwnedSkeleton`).
- [S] `Explorer\User Shell Folders`, `Shell Folders`, `Session Manager` (except the `Environment` segment action), `Winlogon`, `ProfileList`, `IFEO` (report only), `Windows NT\CurrentVersion\Fonts`, `Cryptography`, `SYSTEM\Setup`, `bam`, `Schedule\TaskCache`, `AppModel`, `Appx`, `PackagedCom`, `Component Based Servicing`, `SideBySide`, `WindowsUpdate`.
- `HKLM\SYSTEM` except `Services\<evidenced name>` via SCM and EventLog sources.
- `Uninstall`, `Run*`, `App Paths`, `Installer\*` roots; `RegisteredApplications`; `Explorer` subtree roots.
- [S] `UserChoice` keys.
- `HKU\.DEFAULT`, `S-1-5-18/19/20` (except REG-ARP-MSI rows).

**Derived structural containers.** Every key read by a value-level scanner is structural: Run, StartupApproved\*, SharedDLLs, Environment, AppCompatFlags\Layers, Compatibility Assistant\Store, UserAssist\*\Count, MuiCache, FileExts\*\OpenWithList, ApplicationAssociationToasts, Installer\Folders, FirewallRules, ShimInclusionList, FeatureControl\*. These keys are never deleted as keys. Generated at build time from scanner metadata.

**Agent-origin default-deny:** `SOFTWARE\Microsoft`, `Classes\{Interface,TypeLib,CLSID}`.

**Blast radius:**
- Over 50 keys or 5,000 files, or containing another app's evidence → `TooLarge` / `ContainsOtherApp`.
- Whole-directory quarantine only under a manifest-backed InstallRoot after verify-gone. Otherwise only owned descendants plus empty parents.

**Shared components** (`kb/shared-components.json`): VC++ redistributables, .NET, WebView2, DirectX, VCLibs, WindowsAppRuntime, UI.Xaml, Edge. Never leftovers of another app.

### 5.11 Default summary

| Default | Items |
|---|---|
| Checked (Safe) | Owned shortcuts and pins; App Paths; owned ProgIDs/protocols/verbs/AUMIDs; P values in OpenWithProgids, FileExts and Toasts; proven skeletons (matching baseline); Run + StartupApproved; firewall rules by ID; AppCompat/UserAssist/MuiCache; AppData caches with Tier A; a verified-gone InstallRoot; owned COM/shellex; Tier A services/tasks without dependents; dangling SharedDLLs; PATH segments |
| Unchecked (Likely) | UserData (profiles, unknown AppData folders, `Code\User`, Notepad++ `backup`), exact-name AppData folders, shared IIDs, vendor containers, unanchored KB, AppX packages, dotfiles, other profiles, large trees, anything in forced mode |
| Report-only | UserChoice, live MSI registrations, `%WINDIR%` files, drivers/filters, certificates, network/Winsock/print providers, AppX bookkeeping, TaskCache, IFEO, ClickOnce store, items with CannotBackUp |

---

## 6. Install-time and pre-uninstall evidence

### 6.1 Readers

| Reader | Gives | Phase |
|---|---|---|
| Harvest + reference snapshot | Anchors, subtree baselines, tokens, co-products, Burn children. 50–300 ms per app plus the targeted queries. | M1a |
| Inno `unins*.dat` parser (our own, from issrc `Setup.UninstallLog.pas`) | 448-byte header with CRC32; 4096-byte blocks `{Size, NotSize, CRC}`; records `{Typ:u16, ExtraData:u32, DataSize:u32}`; string markers 0x00–0xFC / 0xFD / 0xFE (negative = UTF-16) / 0xFF; types 0x80–0x8B; `ExtraData & 0x01000000` = 64-bit view; `ExistedBeforeInstall`, `SharedFile`, `RegisteredServer`. Header version gate ≤ 1055; unknown versions skip with a warning. | M1a |
| MSI tables | Cached package, read-only; `MsiGetComponentPathW` (`02:`/`22:` registry key paths); `MsiEnumClientsExW`; `CustomAction` flagged opaque | M1b |
| Burn | ARP bundle values, `Installer\Dependencies`, child packages. `BurnManifest.xml` (UX cab via cabinet.dll FDI) in v2. | M1b |
| AppX manifest | Linked sparse packages | M1b |
| Mozilla `uninstall.log` | Vendor log (format verified in M4) | M4 |
| InstallShield `setup.ilg` | **Not built.** InstallShield coverage comes from FS-UNINSTALLER + references. | — |
| ETW observation (`purge-trace`) | Kernel-Process `0x10\|0x40`, Kernel-File `0x1490\|0x800`, Kernel-Registry `0x7300`. Consumer-side tree filter keyed by (PID, ctime); broker processes counted within the window; `EventsLost` counted; USN `NextUsn` bracketing. | M5 |
| Install & trace | ETW + USN for installs launched through Purge | M7 |
| USN | Launch calibration point; corroboration only, never Tier A | M7 |
| Prefetch / Amcache | Runtime links | v3 |
| NSIS decompilation | Not planned | — |

### 6.2 Pre-harvest cache (for external uninstalls)

- **Admin store** (`ProgramData\Purge\fp`, protected DACL; Tier A for any scope): whenever the broker runs for any reason, at background priority, it copies for **every** installed app:
  - `unins*.dat`;
  - the extracted MSI rows (Registry, ProgId, Extension, Class, Environment);
  - the Mozilla `uninstall.log`;
  - the ext → our-value map;
  - roots, exe names, P, tokens.

  Hash-gated (only changed sources are re-read).
- **User store** (`%LOCALAPPDATA%\Purge\fp`; medium engine after first paint, idle priority, only after icons): the same for per-user apps. Tier A **only for per-user targets** (Rule T); Tier B for machine-scope ones.
- `inventory.changes` uses the stores to attach `RememberedManifest` evidence when an app disappears.

---

## 7. Safety and undo pipeline (`purge-exec`)

`PLAN → VALIDATE → CONSENT (broker) → PREPARE → BACKUP → EXECUTE → VERIFY → COMMIT`. A write-ahead journal spans BACKUP through COMMIT. No BCU or clone deletion code is reused.

### 7.1 Plan

- Normalise (expand, canonicalise, physical hive, views, dedupe).
- **Nesting:** a selected parent absorbs only children that are themselves Safe candidates for the same app. Otherwise the parent becomes "owned descendants + delete-if-empty".
- `EmptyAfterPlan`.
- **Order:**
  1. Close processes
  2. Stop services
  3. Tasks, firewall
  4. Shell/COM/associations
  5. Registry values, then keys (deepest first)
  6. Shortcuts
  7. Files, then folders (deepest first)
  8. Delete services
  9. AppX
  10. Prune empty parents
  11. `SHChangeNotify`
- `plan_hash` = SHA-256 of the canonical plan JSON.

### 7.2 Validate

The gates run at plan time and again **immediately before each item**:

| Gate | Check |
|---|---|
| G1 | Canonical path, final path equal to the lexical path, FileId |
| G2 | Deny-list |
| G3 | TrustedInstaller owner or ACE |
| G4 | Other apps, SharedDLLs, MSI clients |
| G5 | Existed before install |
| G6 | Hard links outside the plan |
| G7 | Sync root or placeholder (`PHCM_EXPOSE_PLACEHOLDERS` set at engine start) |
| G8 | Microsoft system target |
| G9 | User data |
| G10 | Volume is fixed NTFS/ReFS, else `CannotBackUp` (hard, report-only) |
| G11 | REG_LINK |
| G12 | Reversibility None |
| G13 | Delete-if-empty re-check |

Purge never raises its own access (no take-ownership, no ACL edits, no SeBackup/SeRestore for deletes).

### 7.3 Prepare

- Restart Manager registers **files only**.
- Close app, stop service or restart Explorer, each with consent.
- Restore point in parallel when the policy requires one (§7.7).

### 7.4 Backup and storage integrity

- **Install-time setup:** `install.ps1` (v1) creates `C:\ProgramData\Purge` with a protected DACL: owner Administrators, full control for SYSTEM and Administrators, `Users: read` only on `sessions\index.json`.
- **On every use**, the broker opens each session or quarantine dir with `OPEN_REPARSE_POINT` and checks: not a reparse point, owner Administrators or SYSTEM, protected DACL. Otherwise it refuses and renames the directory aside.
- `X:\.purge-q` on other volumes gets the same check on creation and on every use.
- **Registry backup:** `purge.regbackup/1` JSON (raw type DWORD, raw bytes, `name_b64`, class, OWNER/GROUP/DACL SDDL, LastWriteTime, link flag). Written by Purge's own deepest-first walk, which opens every subkey with `REG_OPTION_OPEN_LINK` and refuses links. Flushed and read back before the delete.
- **The journal records a SHA-256 of every backup file**, and undo verifies it.
- A human-readable `.reg` (UTF-16, escaped names, `hex(2)/(7)/(b)`) is generated on request.
- Services, tasks, firewall rules and AppX get full definitions.
- **No verified backup → no delete.**

### 7.5 Execute and quarantine

- **Files and folders:**
  1. `CreateFileW(DELETE|SYNCHRONIZE|FILE_READ_ATTRIBUTES, share R/W/D, OPEN_EXISTING, OPEN_REPARSE_POINT|BACKUP_SEMANTICS)`.
  2. Re-check G1 on that handle.
  3. `SetFileInformationByHandle(FileRenameInfoEx)` into the same-volume quarantine (`ProgramData\Purge\Quarantine\<session>\<op>` or `X:\.purge-q\…`; hidden, system, not indexed). Same volume is checked by volume serial.
- **Registry:** Purge's own link-refusing walk, deepest first (`RegDeleteKeyExW(view)` per key), or `RegDeleteValueW`.
- **Delete-if-empty:** directories use a non-recursive `RemoveDirectory`. Keys are opened, checked with `RegQueryInfoKey` for 0 values and 0 subkeys, then deleted; any count above 0 → "skipped: no longer empty". MultiSz segments are one read-modify-write.
- **Typed actions** go through their APIs.
- **Retries:** sharing violations 3× (100 / 300 / 1000 ms).
- **Results:** missing → `vanished` (success). The batch never aborts, except on a backup write failure.

### 7.6 Locked files and reboot-time operations

The ladder:
1. Retry.
2. Restart Manager.
3. Close the app, stop the service or restart Explorer, with consent.
4. **Boot-time move into quarantine** (`MoveFileExW(…, MOVEFILE_DELAY_UNTIL_REBOOT)`), **only if every ancestor of the source is writable by administrators only.** For user-writable paths, the item is held as "retry at next Purge run" and re-validated through the handle-based G1 at that time.
5. A boot-time delete (Reversibility None) needs its own broker prompt.

**Reconcile** at the next broker start compares the moved item's FileId and volume serial with the recorded values. On a mismatch, it moves the item back immediately and raises an alert. `PendingFileRenameOperations` is never rewritten wholesale; undo removes only our own pairs.

### 7.7 Restore points

- Off by default; automatic for high-risk sessions (services/drivers, more than 500 Classes keys, forced removal).
- Created in the broker with `srclient.dll` `SRSetRestorePointW(APPLICATION_UNINSTALL)`.
- The 24 h throttle is detected by comparing sequence numbers.
- Purge never changes `SystemRestorePointCreationFrequency`.
- Restore points supplement quarantine; they never replace it.

### 7.8 Journal, recovery, undo, expiry

- **Journal:** `journal.jsonl`, `intent` (with backup path and SHA-256) → flush → act → `done`, in groups of up to 64, then `commit` or `aborted`.
- **Recovery** on broker start: probe the real state, then **Resume** or **Roll back**. No TxF/KTM.
- **Typed inverses:**

| Action | Inverse |
|---|---|
| Quarantine move | Handle rename back to the **original recorded path**, after G2/G11 on the destination and a FileId check |
| Key delete | All-or-nothing restore per subtree. An existing key under `Installer\*`, `Services` or COM is a conflict: skip and report. |
| Value delete | Restore the value if absent; if present with different data, conflict |
| MultiSz segment | Re-insert at the recorded index if absent |
| Default-value change | Restore the old value only if the current value equals what Purge wrote |
| MRUList edit | Restore the letter and the order |
| Service | `CreateServiceW` + `ChangeServiceConfig2W` + SDDL; ImagePath must lie inside the original root |
| Task | `RegisterTask(XML)` |
| Firewall | Re-create from the stored instance |
| AppX | None |

  Each action type has its own fidelity test.
- **Expiry proposes; it never acts on its own.** After first paint, the UI reads `sessions\index.json` (Users: read) and shows "N items expire soon" in History. Deletion runs in the broker after its own prompt, with a handle-based walk that never follows reparse points (it deletes the link, never descends), and re-checks volume serial and FileId. **UserData items are exempt** unless confirmed one by one.
- **Size cap:** min(10 GB, 5 % of the volume). Purge never auto-evicts; it refuses a new run that would exceed the cap and explains why.
- **Retention:** file quarantine 30 days; registry/service/task backups 180 days; journal 1 year.
- **The retention is not a lock on the user ("Delete now", DECISIONS 2026-11-23).** It is how long Purge keeps something unasked. The user may have a quarantined item (or all of a session's) deleted before its 30 days end, through the same path as the purge of an expired item: broker-listed ids only, the broker's own prompt naming every item (user data one item per prompt), the same handle walk. The prompt says that this is before the retention date, that it cannot be undone and that Undo no longer restores the item; the journal's `expire` record carries `early`. Only quarantined items: backups and journals are never deleted before their class is due.
- **Learning signal:** undo events are stored as false-positive labels.

### 7.9 Platform notes

- Controlled Folder Access denials are reported clearly; Purge never changes Defender settings.
- **All shipped PE files are signed** with a CA certificate (Smart App Control rejects self-signed). The route is an open decision (§11.3).
- Updates leave unchanged WinAppSDK DLLs untouched, so Defender scans them once per WinAppSDK bump.
- v1 deploy: `install.ps1` into `%ProgramFiles%\Purge` (admin-only ACL). A real installer comes later.

---

## 8. AI agent integration (designed now, shipped in M6)

### 8.1 Invariants (enforced in the engine)

1. The agent points; the engine proves; the user approves **in the broker's high-IL dialog**; the executor acts.
2. `purge-mcp.exe` runs at medium IL with no `purge-exec` and no `purge-win/write` (build test). It writes only to `%LOCALAPPDATA%\Purge\agent\`, which the broker reads as untrusted input. Only protective proposals there take effect without approval.
3. There is no execute, delete, restore, activate or preselect tool, and no `purge://` protocol handler. Agent proposals appear in the UI's Assistant panel with every agent-proposed item **unticked**. The honest limit is stated in §3.1: an agent with a same-user shell equals the user. The broker dialog is the real gate.
4. Ai evidence never counts toward S or the band; it can only lower. Agent `vendor_aliases` or any other raising pack field go through the full lifecycle before activation.
5. Hard blockers, the Guard, reversibility and the gates cannot be changed by any agent input.

### 8.2 MCP tool surface

The SDK (rmcp) and protocol revision are **left unpinned until M6**. The target is the stateless revision current at M6 start (2026-07-28 today) with explicit `scan_id`/`plan_id` handles. Stdio only. No Sampling, Roots, Logging or elicitation for consent. Annotations are honest, but safety never depends on them. Every `inputSchema` has `additionalProperties:false` and `maxLength`/`pattern` limits.

| Kind | Tools |
|---|---|
| Read | `list_programs`, `get_program`, `list_uninstall_sessions`, `get_uninstall_session`, `scan_leftovers`, `get_candidate`, `inspect_location` (names, kinds, sizes, times, value names, redacted path-like values; **never content**; refuses content folders), `find_references`, `explain_guard`, `list_signatures`, `get_signature`, `get_plan`, `get_journal` |
| Propose | `annotate_candidates`, `propose_probes` (the engine runs its own collectors → `candidate` / `rejected{rule_id}` / `duplicate`), `propose_signature` (lint + baseline conflicts + dry matches), `flag_plan_items` (only unticks or annotates), `propose_selection` (stored for the UI; items arrive unticked) |

### 8.3 Probes and signatures

**Probe example:** "%APPDATA%\Mozilla is Firefox's vendor folder" → the engine runs references, ownership, the time window and the Guard. The result is either `rejected: ReferencedByOtherApp(Thunderbird)` or a Likely candidate carrying engine evidence.

**Signatures:** lifecycle per §5.9. Agent packs start `proposed` with max weight 4 and are validated on held-out apps.

### 8.4 Privacy

- AI is off by default.
- Modes: local model (Foundry Local / Ollama), external MCP client, or a later built-in cloud assistant.
- `RedactedPath` (`%USERPROFILE%`, `<SID:u1>`, `<HOST>`), with the mapping kept server-side.
- Never sent: file contents, user name, SIDs, host name.
- An AI outbox log lists every payload served.

### 8.5 Prompt injection

- Strings reach the agent only as `UntrustedString{text, truncated, flags}` JSON fields, escaped and capped at 260 characters.
- The server has no network access.
- AI notes are collapsed and never shown on Likely or UserData rows.
- The rig includes canary apps.

### 8.6 Eval harness

| Run | Content |
|---|---|
| R0 | Engine only |
| R1 | Engine + agent, per model config |
| R2 | Scripted adversarial agent |
| R3 | Injection canaries |
| R4 | Execute + undo round trip |

**Gates:** `danger_listed_agent = 0`, `guard_escapes = 0`, `injection_success = 0`, preselected agent-origin items = ∅. **Reported:** `agent_uplift`.

---

## 9. UI

### 9.1 Stack (decided)

**C# .NET 10 + WinUI 3, Windows App SDK 2.6.x (stable 2.6.5), unpackaged, self-contained, Native AOT, x64.**

Project settings:
- `WindowsPackageType=None`, `EnableMsixTooling=true`, `WindowsAppSDKSelfContained=true`, `PublishAot=true`.
- Component packages only: `Microsoft.WindowsAppSDK.WinUI` + `.Runtime` ("slim", 62.6 MB).
- TFM `net10.0-windows10.0.19041.0` (CsWinRT 2.x) until microsoft-ui-xaml #12625 is fixed.
- **Custom `Main`** (`DISABLE_XAML_GENERATED_MAIN`).

Measured on the dev host (bare bench window, warm, first Rendering tick, p50):

| Variant | p50 |
|---|---|
| Slim self-contained AOT (**the chosen variant**) | **280 ms** (n=7) |
| Metapackage AOT | 264 ms |
| JIT | 312 ms |
| WPF Fluent | 397 ms |
| WebView2 host | ≈ 430 ms |
| Win32 | 27 ms |

An earlier run of the same AOT binaries was bimodal (p50 518–608 ms, max ≈ 1.1 s), most likely from Defender scanning freshly written DLLs. It is tracked as the first-launch-after-install metric.

About 175 ms of the floor is first GPU device creation, which is the same in every WinUI language. Rejected: Rust WinUI (Reactor preview), egui (user constraint), WPF (slower, not WinUI), Tauri/WebView2 (+190 ms, not native), raw Win32 (not Fluent).

**WinAppSDK 2.0 servicing ends 2027-04-29.** A scheduled "WinAppSDK major upgrade + launch re-bench" task sits in M3+ (§11.1). The bench harness is pinned to both versions so the comparison is like for like.

### 9.2 Launch-time plan and measurement

1. **Custom `Main`:**
   - (a) If the "always elevated" setting is on and the process is not elevated → re-exec with runas, then exit.
   - (b) `CreateProcessW` (LibraryImport) for `purge-engine --stdio`, using anonymous pipes and `STARTUPINFOEX` handle inheritance limited to those two pipes, inside a `KILL_ON_JOB_CLOSE` job.
   - (c) Send `engine.hello` + `programs.list`, and read them on a dedicated thread with `Utf8JsonReader` over a pooled buffer.
   - (d) Apply the chosen XamlChangeIds.
   - (e) Start XAML.
2. **`App.xaml`** holds `XamlControlsResources` only.
3. **First frame contains only:** Mica, the `TitleBar` with the search `AutoSuggestBox`, a **plain `StackPanel` of Buttons** (no CommandBar on the first frame), and the virtualized `ListView` (fixed 40 px rows, ≤ 5 elements per template, `x:Phase` for secondary text and icons) with the header Grid. The **SelectorBar tab counts, details pane content, InfoBars and CommandBar overflow** are created on the first `CompositionTarget.Rendering` tick, as a lazily loaded `UserControl`.
4. **Set `ItemsSource` before `Activate()`** when the raw ARP batch has already arrived (the usual case: the reply comes at about 20 ms). The first presented frame then has rows. `programs.patch` fills MSI, Burn and AppX details later.
5. **Icons:** the engine sends viewport-first batches of raw 24×24 BGRA over the pipe. The UI loads them through `WriteableBitmap`. The disk cache is a single atlas keyed by path + mtime.
6. **Later (lazy):** Store tab, leftover review, history, settings, assistant. No `x:Load` under `Window`.
7. **After icons are done, at background I/O priority** (`THREAD_MODE_BACKGROUND_BEGIN`) in the medium engine: `inventory.changes`, the per-user pre-harvest cache, page-cache warm-up of LocalPackage/Classes, reading the expiry index.
8. **XamlChangeIds:** try `DefaultStyleOptimizations`, `IconNoGridOptimization` and `DeferContextFlyoutInit` one at a time, and keep only measured gains. **`OptimizeApplyStyles` stays off on 2.6.5** (ContentDialog regression).
9. **No broker or UAC at launch.**

**Measurement:**
- **(a) Markers relative to process creation:** module init, `OnLaunched`, window ctor, **first Rendering tick** (renamed from "first frame"), **first presented frame** (`DwmFlush` after the first tick, cross-checked with `Microsoft-Windows-Dwm-Core` present events in WPR), first realized container, engine ready, list reply. Emitted to TraceLogging and `PURGE_BENCH_OUT`.
- **(b) `xtask bench-launch`:** interleaved, N = 21, first run dropped, p50/p90, always paired with a **bare-WinUI control** in the same run, deploy flavour recorded. CI fails on a > 10 % regression or a gate breach.
- **(c) S1 skeleton bench in M3**, before the gates are frozen.
- **(d) First launch after install:** copy the publish folder to 5 fresh directories, Defender real-time on, time launches 1–5.
- **(e) Cold after reboot (bare metal):** reboot, wait for logon + 120 s of CPU idle, launch; N ≥ 5 reboots. Measured on the dev host plus one iGPU laptop.
- **(f) VM:** functional start-up on clean Windows; WARP numbers reported only.
- **(g) WPR/WPA** with the XAML provider for deep dives. Deploy size as a secondary metric.
- **(h) S3 page open** with a 2,000-item fixture.

### 9.3 Visual language

- Mica window; `LayerFillColorDefault` cards; Segoe UI Variable; Segoe Fluent Icons; light, dark and high contrast follow the system; accent colour for primary actions only.
- Row height 40 px (compact option 32 px).
- **Band pills:**

  | Pill | Colour |
  |---|---|
  | Safe | `SystemFillColorSuccess` |
  | Likely | `SystemFillColorCaution` |
  | Weak | neutral |
  | Protected | Critical outline, read-only |

- Chips: "User data", "Shared". An undo-arrow icon (struck through for Reversibility None). An "AI" mini-badge.
- All wording is our own (§11.4).
- The broker's consent dialog is a Win32 TaskDialog (v6 common controls) **on purpose**: like UAC, it visibly belongs to the elevated part.

### 9.4 Screens

**Navigation (added when the mockups were aligned).** A left rail with Programs, Uninstall queue, Leftovers, History & undo, Assistant (M6) and Settings. To protect the launch budget, the first frame draws the rail as plain styled Buttons in a `StackPanel`, like the command row. A `NavigationView` is created on the first Rendering tick only if a measurement shows it costs no more than 10 ms. Mockups: the private "Purge UI mockups" canvas artifact (7 artboards, one per screen, plus the broker consent prompt).

#### S1: Main window / program list

```
┌ [P] Purge          [ Search apps, publishers, paths…  ⌕ ]               [🛡 Standard user] ─ □ ✕ ┐
│ ⓘ 2 apps were removed outside Purge (VS Code, Discord).  [Scan for leftovers] [Dismiss]          │
│ Apps 212 · Components 254 · Unnamed 57 · Store … · Recent 6                                     │
│ [🗑 Uninstall] [⚡ Force remove] [✎ Modify] [⊖ Remove entry]  [⋯]                    ☐ Select   │
├────────────────────────────────────────────────────────────────┬────────────────────────────────┤
│ Name ▲                      Publisher        Size    Installed │ [icon 64] Mozilla Firefox      │
│ [ic] 7-Zip 24.08 (x64)      Igor Pavlov      5.6 MB  2026-11-02│ 146.0.1 · Mozilla · 252 MB     │
│ [ic] Git 2.51.0             The Git Dev…     342 MB  2026-10-20│ Installed 2026-11-10 · machine │
│ [ic] Mozilla Firefox 146    Mozilla          252 MB  2026-11-10│ NSIS · 64-bit · signed Mozilla │
│ ▸[ic] Python 3.12.7 (64-bit) Python Softw…   112 MB  2026-11-10│ Location  C:\Program Files\…   │
│     └ Python Launcher        Python Softw…   1.3 MB  2026-11-10│ Uninstall  "…\helper.exe"      │
│ …                                                              │ Quiet      "…\helper.exe" /S   │
│                                                                │ Related    Maintenance Service │
│                                                                │ [Uninstall] [Open folder] [⋯]  │
└ 212 apps · 12.4 GB                                                    Engine ready · 19 ms ───────┘
```

**Title bar:**
- `TitleBar` with the app icon and "Purge".
- An `AutoSuggestBox` that searches name, publisher, version and path.
- An elevation chip ("Standard user" / "Administrator"; a click explains when admin is needed).

**InfoBar** (Informational, created after the first tick): apps removed outside Purge → "Scan for leftovers" / "Dismiss".

**SelectorBar** (counts fill in after the first tick):
- Apps
- Components (`SystemComponent`)
- Unnamed (no DisplayName)
- Store (lazy)
- Recent (installed in the last 14 days)

**Command row:**
- First frame: plain Buttons for Uninstall, Force remove, Modify, Remove entry.
- The `⋯` flyout (lazy): open folder, open registry key, website, search online, export JSON, refresh.
- The "Select" toggle switches to multi-select checkboxes for batches.

**List rows:**
- 24 px icon (placeholder until loaded); Name with version as secondary text; Publisher; Size (estimated in italic until measured); Installed date.
- Badges: `32-bit`, `Per-user`, installer kind (`MSI`/`Inno`/`NSIS`/`Burn`/`MSIX`/`Sparse`/`Squirrel`), amber `Leftovers`.
- Child rows (updates, Burn children, related packages) sit indented under their parent with a chevron.
- Columns sort when the header is clicked.

**Details pane** (320 px, collapsible, lazy):
- 64 px icon, name, version, publisher, signer, size, install date and scope, installer kind and bitness.
- Location (link), uninstall and quiet strings (monospace, copyable), product code, registry key, related entries.
- Action buttons.

**Status strip:** count and size; engine status.

#### S2: Uninstall flow

1. **Click Uninstall:** the elevation request starts immediately for machine-scope apps (UAC appears; the broker starts indexing). Per-user apps need no UAC.
2. **Confirm** (`ContentDialog`):
   - icon and name (or "3 apps" with a list);
   - steps "1 · Record what the app registered · 2 · Run its uninstaller · 3 · Review leftovers";
   - **the exact command and its signer** ("Signed by Mozilla Corporation");
   - toggles: Quiet (shows the command), Restore point (Auto/On/Off), "Close running apps" with a list (firefox.exe ×5);
   - buttons: "Uninstall" (primary) and "Cancel".
   - The broker's index status shows as a small footer line ("Preparing… 1.2 s").
3. **Progress** (in-window page; the list stays usable). Vertical stepper:
   - "Recording what Firefox registered": "412 registrations · Inno log 10,504 records · also removes: Mozilla Maintenance Service";
   - "Running uninstaller": process name, elapsed time, "waiting for helper processes";
   - "Checking it's really gone": ARP / MSI / main exe;
   - "Finding leftovers": scanner names ticking, items found;
   - "Ready to review".

   Batches show a queue with per-app state.

   **Error InfoBars:**
   - Exit code ("Uninstaller reported 1602: cancelled") → "Run forced cleanup" / "Retry".
   - Verify-gone failure: "Firefox still appears installed. The uninstaller may have repaired or modified it instead. Leftovers will be shown but nothing will be preselected."
   - Reboot needed.

#### S3: Leftover review (the core screen)

```
┌ ← Mozilla Firefox — leftovers                                          [✦ Assistant] ┐
│ Uninstalled 12:04 · 31 found · 22 selected · 18.4 MB · restorable for 30 days         │
│ ⚠ 3 items kept: shared with Mozilla Thunderbird.             [Show protected]         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ☑ ▾ Files & folders (6)                                     12.1 MB   (toggles Safe only)│
│   ☑   📁 C:\Program Files\Mozilla Firefox\uninstall      [Safe]   1.2 MB  ↶            │
│   ☐   📁 %APPDATA%\Mozilla\Firefox\Profiles   [Likely][User data] 10.6 MB  ↶           │
│        ▾ Why: ● Firefox's config referenced this folder before uninstall               │
│               ◐ Named Mozilla\Firefox (vendor alias of Firefox's publisher)            │
│               ⚠ Contains your profiles, bookmarks and passwords                        │
│ ☑ ▾ Registry (14)                                                                      │
│   ☑   🔑 HKLM\SOFTWARE\Mozilla\Firefox                   [Safe]           ↶            │
│        ▾ Why: ● Values pointed to C:\Program Files\Mozilla Firefox before uninstall    │
│ ☑ ▸ File associations & protocols (5)   ☑ ▸ Shell & COM (4)   ☐ ▸ Shared COM (3) Likely │
│ ☑ ▸ Services & tasks (2)   ☑ ▸ Privacy traces (3)   ☐ ▸ Packages (0)                    │
│ ☐ Show weak matches (2)                                                                │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ Report only: Default browser was Firefox. Choose a new one in Settings  [Open]         │
│                                       [Skip]   [🛡 Move 22 items to quarantine…]        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

**Implementation:** a **flattened, virtualized `ListView`** (group header rows, indent levels, hand-computed tri-state CheckBox; expanding inserts rows). It is not a TreeView. Large sets collapse to one node ("135 file extensions").

**Header:** back, app name, summary, and the "Assistant" toggle (only when AI is enabled).

**InfoBars:**
- Warning: "N items kept: shared with <app>" → "Show protected".
- Informational: "<Python Launcher> is still installed and owns 13 related registrations. Uninstall it too?" → "Add to queue". Shown only when no other dependent remains.
- Forced or verify-gone mode: "Nothing preselected because <reason>".

**Groups**, each with count and size:
1. Files & folders
2. Registry
3. File associations & protocols
4. Shell & COM
5. Shared COM (Likely)
6. Services & tasks
7. Packages
8. Privacy traces

**Group checkboxes toggle only Safe items.** Likely and UserData items need a per-item tick.

**Rows:**
- checkbox; kind icon;
- canonical path in monospace with middle ellipsis (tooltip shows the full path; right-click copies);
- band pill; harm chip; size; reversibility icon; "AI" mini-badge.

**Expanded "Why"** (v1 evidence only):
- engine evidence lines with a tier glyph (● explicit, ◐ corroborating, ○ name) and the source ("Git uninstall log", "recorded before uninstall", "MSI table of Node.js", "knowledge pack mozilla.firefox v3");
- blockers in red;
- the AI note last, collapsed.

Actions: "Open in Explorer / Registry Editor" and "Always keep" (writes a protective rule).

**Protected section** (collapsed, read-only): e.g. "Present on clean Windows 11 Pro 26300", "Owned by Python Launcher (installed)", "Shared with Thunderbird".

**Report-only section:** UserChoice, Windows-managed AppX residue, `%WINDIR%` files, drivers, certificates, ClickOnce store, items that cannot be backed up. Each has an "Open Settings" link where it applies.

**Footer:**
- "Show weak matches";
- "Skip";
- the primary accent button "Move N items to quarantine…". It sends `plan.create` + `plan.execute`. The UI then shows "Confirm in the Purge security prompt", and the broker TaskDialog lists counts, every UserData, agent-origin, Reversibility-None, boot-time and over-1-GB item, and the hash.

**Result page:**
- Removed, Already gone, Waiting for restart (InfoBar "Restart now / later"), Failed (expandable), Deferred (shared with an app still in the queue).
- "Undo all" / "Done".

#### S4: History and undo

- Sessions, newest first. Each row: date and time, app(s), count, size, a "days left" ring, reversibility (Full / Partial), state (Committed / Waiting for restart / Interrupted).
- **Recovery InfoBar:** "A cleanup was interrupted at 14:02 (37 of 52 done)" → "Resume" / "Roll back" (both go through broker consent).
- **"Expiring soon" InfoBar:** "41 items (1.2 GB) are past 30 days" → "Review and delete…" (broker prompt; UserData items listed one by one).
- **Detail:** the S3 list with per-item state (Quarantined, Removed, Restored, Purged, Failed, Conflict). "Restore selected" / "Restore all". "Export journal (JSON)", "Export registry backup (.reg)".
- **Footer:** quarantine usage per volume ("1.8 GB of 10 GB on C:"), "Empty quarantine…" (danger-styled; the broker prompt names the size and states "cannot be undone").

#### S5: Settings

A single scrolling page of `Expander` cards:

| Card | Settings |
|---|---|
| Appearance | Theme; Compact rows |
| Startup | Always start as administrator (explains the UAC prompt on every launch and the loss of drag and drop) |
| Uninstall | Prefer quiet uninstall; After uninstall: Ask / Scan automatically / Don't scan; Restore point: Off / High-risk only (default) / Always; Close running apps without asking |
| Leftovers | Show weak matches; Pre-select app caches (on); Pre-select user data (off, with warning); Include other user profiles (read-only scan) |
| Quarantine | Retention days; size cap; per-volume locations (read-only) |
| Knowledge packs | Shipped packs with version and status; disable per pack; "Always keep" rules list (removable) |
| AI assistant (M6) | Off (default) / Local model / External MCP client; redaction (locked on for external); "View AI outbox"; "Copy MCP config" |
| Diagnostics | Last 10 launch markers; Open log folder; Export diagnostics |
| About | Versions (app, engine, policy, baselines available); Licenses (BCU NOTICE, WinAppSDK, crates) |

#### S6: AI assistant panel (M6)

- Right pane, 380 px, inside S3 and S4. Header: "Assistant · suggestions only", model, privacy chip.
- **Body:** structured cards, not free chat:
  - Annotation: "Ranked 3 items as likely shared" → links.
  - Probe: proposal → engine verdict ("Rejected: still used by Mozilla Thunderbird (OWN-OTHER)" / "Added as Likely, unchecked: the engine found 2 references").
  - Flag: "Unticked %APPDATA%\Foo: possibly user data" → "Re-tick".
  - Signature: lifecycle stepper with **Approve** (approving a raising signature goes through the broker prompt).
- **Footer:** a prompt box. There is no execute button. "Open AI outbox".

#### S7: Small dialogs

- **Force remove:** app or folder picker; a mandatory "I understand this skips the vendor uninstaller and nothing will be preselected" checkbox.
- **Remove entry:** key path; backed up; refused for MSI-registered products ("use Uninstall").
- **First-elevation explanation.**
- **Close running apps:** list with "Close" / "End task".
- **Restart Explorer:** explains that loaded shell extensions must be released.
- **Admin prompt cancelled:** InfoBar.

---

## 10. Test and benchmark strategy

### 10.1 Unit and integration tests

- **`RegistrySource` / `FileSystemSource` fixtures:** JSON trees from value-level VM captures, and **offline hives via offreg** (no admin, no mounting).
- **Golden tests** per scanner and policy version.
- **Guard property and fuzz tests:** path forms, 8.3, `\\?\`, ADS, junction parents, REG_LINK, `CurrentControlSet` / `_Classes` canonicalisation, WOW64, HKCR.
- **Parser tests:** Inno logs (Git, VS Code, WinMerge, UniGetUI plus synthetic versions); MSI sample databases; the `.reg` generator.
- **Regression tests:**
  - Notepad++ vs `Notepad.lnk`
  - Python 3.12 + 3.13
  - .NET Hosting vs `Microsoft.NET`
  - Steam / `steamapps`
  - InstallLocation `C:\Program Files\`
  - every VC++ redist installed (empty token set)
  - Firefox `TaskBarIDs` value names
  - the BCU nested-delete sequence
  - the BCU missing-path COM case
  - non-English Windows
- **C#:** DTO round-trips, ViewModels, bench.
- **`xtask ci`:** fmt, clippy, tests, `check-deps`, `ui-strings`, `scanner-coverage`, DTO schema drift.

### 10.2 VM rig as the release gate

**M0 fixes:**
1. `VBoxManage snapshot restore` before each app.
2. Capture `snap1` after install.
3. **Delete `$Noise` from `guest\lib.ps1`.** Capture everything raw and filter only in the scorer.
4. **Parse values from the `reg export` output the rig already produces** (names, types, data hashes) plus key LastWriteTime.
5. Add roots: the profile root (depth-1 files and dirs), `C:\Windows\Prefetch`, `C:\Windows\Installer`, `Session Manager\Environment`, `HKU\<SID>\Environment`, the whole of `HKU\<SID>_Classes`, `SharedAccess\…\FirewallRules` values, `HKU\.DEFAULT`, `S-1-5-18`.
6. Structured lists: AppX (all users, provisioned), tasks, services, firewall (`Get-NetFirewallRule`), certificates, fonts.
7. Ambient set from 3 null runs.
8. Record the uninstaller's `[t0, t1]`.
9. Re-run the 8 apps, relabel the truth (L10, L11, contamination). **Discard the old `snap0` files as baselines.**
10. `score.ps1` reads the plan JSON. It compares at the Target granularity (RegValue / RegKey / Path, so a value added to a pre-existing key is not danger) and reports §1.3 macro and per-kind/per-scanner metrics.

**VMs:**
- **Clean-LTSC** (existing).
- **Clean-Pro** on the host's channel and build: Purge's (edition, build) baselines are built from clean snapshots that never had a test app.
- **Dirty-baseline** snapshot: Office C2R, Visual Studio, Thunderbird, NVDA, Steam with a library on D:, OneDrive with Known Folder Move, Zotero with a library, portable tools in `C:\Tools`, two Pythons, Node + VS Code, plus planted user files inside app roots and AppData.

**Runs per app:**

| Run | Content |
|---|---|
| R0 | Engine plan, `post_uninstall` |
| R-ext | Vendor uninstall outside Purge, then an `external` scan |
| R-force | No uninstaller (dir deleted); truth = snap1 − snap0 |
| — | Execute, then deep round-trip undo |
| — | Crash injection (`PURGE_FAULT_AT`) |
| — | Lock + reboot (M2) |
| — | Functional start-up |

**Traps:**
- *M2 (PowerShell-built):* junctions/symlinks/hard links, a junction parent inside the install dir, long paths, trailing dots, read-only/hidden files, REG_LINK, a TrustedInstaller-owned folder and key, attribute-faked placeholders, a ProgramData\Purge pre-created by a user, a planted junction for boot-time moves, a forged user-store fingerprint.
- *M4 (installer-built):* an app named or installed into "Update"; an install into Documents; a CloudMirror sync root; a stale duplicate ARP entry; a modify-instead-of-uninstall; a cancelled uninstall returning 0; an offline-drive DanglingRef; an app whose data dir is `D:\Library`; injection canaries; a second profile; over-the-shoulder elevation; Defender's `Mozilla\NativeMessagingHosts` and `ShimInclusionList` never offered whole.

### 10.3 `undo_fidelity` definition

Compared fields:
- registry: target identity, value type, data hash, key SDDL;
- files: content hash, attributes, ADS list, link count, and FileId where a rename was used;
- services, tasks and firewall rules: the definition minus runtime state.

Excluded on purpose: registry LastWriteTime, parent-directory LastWriteTime, 8.3 names (unless referenced), the ambient set.

### 10.4 App corpus (✓ = already tested; all re-run in M0)

| # | App | Installer | Covers |
|---|---|---|---|
| 1 | Mozilla Firefox ✓ | NSIS | Vendor ≠ product, tokens, co-removed service, task, shared IIDs |
| 2 | Mozilla Thunderbird (with Firefox) | NSIS | Shared vendor protection |
| 3 | Notepad++ ✓ | NSIS + sparse | Notepad.lnk regression, sparse package, user-data `backup\` |
| 4 | VLC | NSIS | Associations, protocols, AutoPlay |
| 5 | OBS Studio | NSIS | DirectShow/MF COM (COM-MEDIA) |
| 6 | VS Code system ✓ | Inno + sparse | Associations, toasts, PATH, verbs |
| 7 | VS Code user | Inno, per-user | `%LOCALAPPDATA%\Programs`, HKU Classes, Rule T |
| 8 | Git ✓ | Inno | ProvenOwnedSkeleton, PATH, dotfiles |
| 9 | WinMerge | Inno | `Thingamahoochie`, shell extension |
| 10 | 7-Zip ✓ | MSI | Shell-ext CLSID, Defender ambient |
| 11 | Node.js 20 ✓ | MSI | MSI Environment (user npm PATH) |
| 12 | PowerShell 7 | MSI | PATH, App Paths, context menu |
| 13 | Eclipse Temurin JDK | MSI | `JAVA_HOME`, shared vendor dir |
| 14 | Google Chrome enterprise (+ Edge present) | MSI | Chromium overlap, mega-vendor |
| 15 | Python 3.12 ✓ | Burn | Row-granular launcher ownership, Package Cache |
| 16 | Python 3.13 (with 3.12) | Burn | Shared Python keys, suggestion suppression |
| 17 | VC++ 2015–2022 ✓ | Burn | Shared runtime, empty token set |
| 18 | .NET 8 Desktop + Hosting Bundle | Burn | Shared `dotnet`, refcounts |
| 19 | PowerToys (machine) | Burn/WiX + sparse | Sparse packages, task, services |
| 20 | Discord | Squirrel | `Update.exe`, `packages\`, `--processStart` shortcuts |
| 21 | GitHub Desktop | Squirrel | Protocol, AUMID |
| 22 | Obsidian | electron-builder NSIS (per-user) | `<name>-updater`, appId GUID key |
| 23 | Windows Terminal | MSIX | API removal |
| 24 | Our ClickOnce test app | ClickOnce | Report-only store, `.appref-ms` |
| 25 | Process Explorer | Portable | `scan --path`, `HKCU\Software\Sysinternals` |
| 26 | A winget portable package (e.g. jq) | winget portable | `WinGet\Links` dangling symlinks |
| 27 | One InstallShield app (chosen in M0) | InstallShield | `InstallShield Installation Information`, engine-dir deny |
| 28 | Steam + a free game | NSIS + Steam | `steamapps` protection |
| 29 | Tailscale | MSI | Service, firewall. Network/driver items **report-only** (SYS-NETWORK); excluded from recall gates until v2 |

---

## 11. Milestones, risks, licensing

### 11.1 Milestones (engine first)

| M | Scope | Exit criteria |
|---|---|---|
| **M0 Hygiene + rig** | Repo layout; `NOTICE`; `xtask ui-strings`; clone docs quarantined outside the repo; rig fixes 1–10; Clean-Pro + dirty-baseline VMs; (edition, build) baselines; corpus scripted; `PARITY.md` updated. *UI shell skeleton may start in parallel; it does not gate anything.* | Raw value-level capture; null-run ambient; the 8 apps re-run under restore; per-app numbers frozen; old clone/UT/BCU results reproduced under the new scorer. |
| **M1a Engine dry run I** | `purge-model/win/source/inventory/identity/harvest(Inno, ref snapshot, tokens, co-products)/index(targeted)/policy/guard(read)`; minimal uninstall runner; CLI (§3.4); scanners FS-INSTALLDIR/UNINSTALLER/APPDATA/VENDORPARENT/SHORTCUTS, REG-SOFTWARE/APPPATHS/RUN/ENV, REF-ANY, CLS-PROGID/ASSOC/FILEEXTS/TOASTS/AUMID/VERBS/PROTOCOL/REGAPPS | Dry-run plans for VS Code (sys + user), Git, Firefox (+ Thunderbird), Notepad++: §1.4 bands met, danger 0, `precision_safe` 100 %, `userdata_preselected` 0, a better recall than BCU on the same runs. Inventory entry set equals the raw enumeration (`lists-registry.json`) plus `MsiEnumProductsEx`, with every difference explained. |
| **M1b Engine dry run II** | MSI tables + ownership (rows, all contexts), Burn children, COM-CLASS/INTERFACE/SHELLEX core, SYS-SERVICE/TASK/FIREWALL/APPX/BURNDEPS, FS-PKGCACHE/WER, REG-ARP-MSI/SHAREDDLLS/INSTFOLDERS/PRIVACY (incl. MuiCache)/DIAG (Tracing, EventLog) | 7-Zip, Python 3.12 (+3.13), Node, VC++, PowerShell, Temurin: bands met, protected_correct 100 %, danger 0 on the clean and dirty VMs. |
| **M2 Executor** | `purge-exec` (quarantine, regbackup with link-refusing walk, journal + hashes, typed inverses, locked-file ladder with the admin-only-ancestor rule, restore point), storage integrity checks, `install.ps1`, `exec` via the `rig-exec` CLI | M2 traps: 0 escapes. Round-trip fidelity 100 % per action type. Crash injection resume/rollback. Lock + reboot reconcile. Nested-delete sequence. Expiry walk never crosses a junction. |
| **M3 UI + broker** | WinUI shell (S1, S2, S3, S4, S7), custom Main, launch bench + S1 skeleton bench, `--broker` (pipe, identity, consent TaskDialog), per-user runner in the medium engine, `programs.patch`, icon batches. Scheduled task: **WinAppSDK major upgrade + re-bench before 2027-04-29.** | §1.3 launch gates (names-visible primary; first launch after install; bare-metal cold). End-to-end on the M1 apps via UI automation. Broker consent cannot be driven from medium IL (manual `SendInput` test). Starts on clean Windows. |
| **M4 Coverage** | Remaining scanners (REG-EXEKEYED, NOTIFY, ACTIVESETUP, NMH, OFFICEADDIN, BROWSEREXT, CLS-AUTOPLAY, COM-MEDIA, COM-SHELLEX rest, FS-DOTFILES/PREFETCH/TEMP/DANGLINGLINKS, SYS-DEFENDER/NETWORK, X-SQUIRREL/CLICKONCE/SYSTIDY); external + forced modes; pre-harvest cache (admin + user stores); static KB packs; other profiles read-only; S5; installer-built traps | Full corpus: `recall_visible` ≥ 90 % macro (no app < 75 %), `recall_safe` ≥ 75 %, `recall_ext` ≥ 70 %, `recall_force` ≥ 60 %, danger 0, `userdata_preselected` 0, `precision_safe` 100 %. |
| **M5 Observation** | `purge-trace` ETW during uninstalls; Traced evidence | Recall uplift on NSIS apps with no rise in danger; `EventsLost` reported. |
| **M6 AI agent** | `purge-mcp` (SDK/protocol pinned now), Propose APIs, KB lifecycle + approvals, S6, eval R1–R3 | `check-deps`; R2/R3 gates at 0; `agent_uplift` reported. |
| **M8 Setup soak (release 1.3)** | Mass testing on randomised machines. A seeded generator picks the app set, versions, install order and actions (install, update, repair, uninstall, reinstall), plus user data and the Windows edition/build. The seed is recorded, so every run replays exactly. Pairs of apps known to share something (runtimes, Package Cache, Python/Java/Node, COM, file types) go first; random filler fills the rest. Runs go off the laptop (cloud VMs / CI runners: E: holds one VM at a time). The scorer judges the danger side: is anything of another installed app or of Windows offered or preselected? Recall is reported, not gated. A finding is minimised to a fixed case that joins the regular gates. Report-only: a soak run never gates a release. | Thousands of seeded setups on at least 3 Windows builds (editions included), every corpus app removed in at least 50 different neighbourhoods: `danger_offered` 0 and `userdata_preselected` 0 over all of them; every finding minimised to a fixed case and fixed. |
| **M7 v2 extras** | Install & trace (ETW + USN), startup manager, Steam/Scoop/Choco/features, Program Files orphans, coupled driver removal, real installer, arm64 once hardware is in the rig | Per-feature exit tests. |

### 11.2 Risks and mitigations

| Risk | Mitigation |
|---|---|
| A Windows component is missing from the deny-list or baseline | (edition, build) baselines; no Classes key deletes without a matching baseline; dirty-baseline VM; danger gates; quarantine. |
| Wrong root or live app (modify, repair, stale ARP) | `validate_root`, verify-gone, live-reference blockers, Rule T, traps. |
| A value-level fact deletes a container | Scope typing; auto-derived structural containers. |
| Same-user automation approves a plan | Broker high-IL consent; honest trust statement. |
| Users plant junctions in quarantine or ProgramData | Installer-created DACL; per-use checks; non-traversing walk; admin-only-ancestor rule for boot moves. |
| Sparse-package misattribution | No publisher linking; external location or harvest only; Likely by default. |
| Firewall rules sharing names | Delete by InstanceID only. |
| `EffectiveExternalPath` empty | Harvested family fallback; otherwise not linked. Checked in M0. |
| Inno format changes | Version gate; fall back to the harvest. |
| Missing LocalPackage | `MsiPackageUnreadable` soft blocker. |
| LastWriteTime semantics | Weight 1, never decisive. |
| ETW lost events | Counted; the harvest stays primary. |
| GPU/Defender dominating launch | Bare-WinUI-relative gate; signing; unchanged-DLL reuse; first-launch metric. |
| WinAppSDK 2.x end of servicing (2027-04-29) | Scheduled upgrade + re-bench in M3+. |
| CsWinRT 3 churn | Stay on 2.x until #12625 is fixed. |
| Rust port velocity | Revisit trigger in §3.5. |
| UT contamination | `ui-strings` CI; no `programs.rs`; quarantined docs never used as agent context. |
| Quarantine fills the disk | Cap with refusal, never silent eviction. |

### 11.3 Open user decisions

1. Confirm `asInvoker` + broker (consent in the broker dialog) instead of "always elevated".
2. User data unchecked by default; unknown AppData folders treated as user data.
3. Restore point default: high-risk only.
4. Code-signing route: CA certificate vs Microsoft's hosted signing.
5. Items owned by remaining Permanent packages are only handled by suggesting that package's uninstall (recommended).
6. Building a Clean-Pro VM that tracks the host's Insider channel (needed for skeleton removal on the host).

### 11.4 Licensing and attribution

- **BCU (Apache-2.0):**
  - `NOTICE` reproduces BCU's notice;
  - every ported file keeps `Copyright (c) 2017 Marcin Szeniak`, adds "Modified by Purge" and the `// Ported from BCU: source/<path> (Apache-2.0)` marker;
  - About lists the licence.
- **UT:** no code, binaries, strings, constants, decompilations, derived rules or wording. `xtask ui-strings` matches every string literal of 12 or more characters in `ui/**` and `crates/**` against a local, uncommitted copy of `English.xml` (path via an environment variable) and fails on any match. UT taxonomy names are not used. `programs.rs` is not used. `draft_clone\docs\decompiled\evidence-bundle.json`, `MECHANICS.md`, `mechanics.json` and `CLAUDE.md` stay outside the repo and are never agent context.
- **Inno Setup:** our parser is written from the published format; no issrc code is copied.
- **Data:** winget-pkgs (MIT, attributed), Scoop Main (Unlicense), the `chocolatey-community/chocolatey-packages` repository only (Apache-2.0). Winapp2 and BleachBit are reference only.
- **Runtime:** WinAppSDK self-contained (MIT WinUI + Microsoft redistribution terms); .NET 10 AOT; crates via `cargo-about` → `THIRD_PARTY.md`.

### 11.5 Required `PARITY.md` edits

1. **Elevation:** replace "always runs elevated via manifest" with "asInvoker UI + on-demand elevated broker; final consent in the broker; optional 'always start as administrator'".
2. **AI:** replace "AI cannot add candidates" with "AI may propose probes and signatures; only engine evidence creates candidates; agent items are never preselected; AI evidence never raises a band; AI never executes".
3. **Store apps:** v2 → v1 (PackageManager, lazy tab; sparse packages linked only by external location or harvest).
4. **Backup:** replace ".reg + zipped files" with "same-volume quarantine + lossless JSON registry backup (.reg on demand) + hashed journal + typed undo; restore point optional".
5. **Leftover wizard:** add the pre-uninstall harvest, verify-gone, Inno/MSI/Burn readers, the scanner catalog of §5.6, and the evidence model in place of BCU confidence.
6. **Categories:** Purge's own tab names (Apps / Components / Unnamed / Store / Recent).
7. **Clone reuse:** "list builder from the clone" becomes "inventory written fresh from BCU and Microsoft docs".

---

## Appendix A: Glossary

| Term | Meaning |
|---|---|
| Tier A | A checked fact from the system or the installer's own record (from an admin-trusted source when the target is machine-scope) |
| Scope | Whether evidence supports a value or a key target |
| Rule T | Evidence from a user-writable source never attributes machine-scope targets |
| Verify-gone | ARP gone, MSI UNKNOWN in all contexts, main exes gone |
| ProvenOwnedSkeleton | A key whose whole subtree was attributed to the app at harvest and is now empty and not in the baseline |
| Safe / Likely / Weak / Blocked | Checked / visible but unchecked / hidden / protected |

## Appendix B: Review log

**Safety review**

| # | Sev | Issue | Resolution | Where |
|---|---|---|---|---|
| S1 | Crit | Data dirs found by references became app roots, so `InsideAppRoot` could quarantine a user's library | Root kinds introduced. Only an InstallRoot yields `InsideInstallRoot`. A ReferencedDataDir is Tier B, UserData and never a whole-dir target. Traps added. | §5.2, §5.3, §10.2 |
| S2 | Crit | "Validated root" undefined; inferred, user-writable and System32 roots | `validate_root()` specified; InferredRoot is Tier B; Rule T; `MicrosoftSystemTarget` applies regardless of root | §5.2, §5.3 |
| S3 | Crit | Value evidence promoted container keys; registry deny-list gaps; BCU's Microsoft skip dropped | Scope typing; auto-derived structural containers; missing roots added; `SOFTWARE\Microsoft` key deletes need manifest, trace or proven skeleton; typed COM key rule | §5.3, §5.10 |
| S4 | Crit | False UIPI claim; HMAC readable at medium IL; headless `exec --confirm` | Consent moved into the broker's high-IL TaskDialog; HMAC dropped; broker executes only its own plans; headless exec only in `rig-exec` builds; honest trust statement | §3.1, §3.4, §8.1 |
| S5 | Crit | Scan after a modify/repair/cancel or a stale ARP entry could quarantine a live install | Verify-gone gate; live-reference and modified-after blockers on FS-INSTALLDIR; forced mode without preselection; traps | §4.4, §5.6, §5.8.3, §10.2 |
| S6 | Crit | Quarantine expiry was a silent permanent delete that could follow reparse points | Expiry only proposes; broker prompt; non-traversing handle walk; no auto-evict; UserData exempt | §7.8 |
| S7 | Crit | Boot-time MoveFileEx on user-writable paths (planted junction) | Allowed only when every ancestor is admin-only writable; otherwise retry at the next run; reconcile checks FileId and moves back on mismatch | §7.6 |
| S8 | Major | Wrong MSI condition (> 1 client); per-context state checks; missing LocalPackage | Any client other than the target blocks; all users and contexts; `MsiPackageUnreadable` soft blocker | §5.3, §5.5 |
| S9 | Major | Shared Gecko IIDs, Mozilla-<guid> update root, profiles.ini, related-product suggestions | `shared-iids.json`; Interface keys Likely; hash-matched subfolder only; profiles.ini kept; suggestion only when no other dependent remains; Firefox measured with Thunderbird | §5.6, §5.7.2, §1.4 |
| S10 | Major | Ownership blind to unregistered or uninstalled siblings; vendor folder absorbing Thunderbird's data | Carry-over rule; vendor containers delete-if-empty only; OlderThanInstall is a soft blocker; unloaded profiles read via offreg | §5.3, §5.5 |
| S11 | Major | AI +2 could lift an item into Safe; agent aliases; agent-shaped notes; `purge://` | Ai excluded from S; raising pack fields go through the lifecycle; notes collapsed; agent items unticked; no protocol handler | §5.8.1, §8.1 |
| S12 | Major | Windows ProgIDs could enter P; default-value loss; no-baseline fallback on the host | Stricter P rule; modified pre-existing ProgIDs restored at value level; vendor-backup restore; no Classes key deletes without a matching baseline; TrustedInstaller ACE block | §5.4, §5.7.1 |
| S13 | Major | Reparse traversal in the index; REG_LINK handling; `RegDeleteTreeW` | Index never traverses; final ≠ lexical → block; own link-refusing walk; ControlSet00N and `_Classes` canonicalisation | §5.10, §7.4, §7.5 |
| S14 | Major | `INetFwRules::Remove(name)` is not unique | Delete by InstanceID through MSFT_NetFirewallRule; App= re-checked; no GPO/MDM | §5.6 |
| S15 | Major | AppX linked by publisher; Remove/Deprovision for all users | No publisher linking; exclusions for framework/Store/system packages; deprovision rules; Likely; "recommended" label dropped | §4.1, §5.6 |
| S16 | Major | ProgramData\Purge and `.purge-q` could be pre-created by a user; backup tampering | Installer-created DACL; per-use owner, DACL and reparse checks; journal hashes; service-undo ImagePath check | §7.4, §7.8 |
| S17 | Major | Broker running HKU or user-writable uninstallers at high IL | Per-user entries run in the medium engine; broker only for admin-only paths; command and signer shown | §4.4, §9.4 S2 |
| S18 | Major | Undo silently skipped in-place edits; merge into reinstalled keys | Typed inverses per action; all-or-nothing per subtree; conflict list; fidelity test per type | §7.8 |
| S19 | Major | Group checkbox ticks UserData; parent absorbs children | Group checkbox toggles Safe only; Safe-only absorb; unknown AppData = UserData; UserData in the consent list; KB `user_data` | §5.6, §7.1, §9.4 S3 |
| S20 | Major | DanglingRef on unavailable volumes; forged remembered roots | Strict dangling definition; remembered data in the admin store, or Tier B under Rule T | §5.3, §6.2 |
| S21 | Major | Empty token set matches every name | ≥ 1 (≥ 2 for mega-vendors) distinctive token, else name evidence disabled; VC++ unit test | §5.4 |
| S22 | Major | Deny-list semantics ambiguous; secret stores, dotfiles, sync-root subtrees missing | [S]/[E]/[E+A] annotations; secrets and dotfiles added; sync roots are subtree blocks | §5.10 |
| S23 | Major | `danger_listed` only checked against a clean `snap0` | Dirty-baseline VM, `userdata_preselected`, new traps | §1.3, §10.2 |
| S24 | Major | Batch executed shared items before the co-owner's uninstall | MultiTargetOwner deferred until every co-owner is gone | §5.8.4 |
| Minor | — | CannotBackUp semantics; KB load paths; shortcut Resolve and high-IL parsing; delete-if-empty race | CannotBackUp hard/report-only; raising rules from admin locations only; RAWPATH without Resolve, per-user parsing at medium IL; delete-if-empty re-check | §5.3, §5.9, §5.6, §7.5 |

**Coverage review**

| # | Sev | Issue | Resolution | Where |
|---|---|---|---|---|
| C1 | Crit | `lib.ps1 $Noise` and the root list hide a third of the scanner targets | `$Noise` deleted; roots added; `scanner-coverage` CI; uncovered scanners cannot emit Safe | §10.2, §5.6 |
| C2 | Crit | Git/Firefox targets unreachable under the weights | `ProvenOwnedSkeleton`, `HarvestedToken`, shipped anchored KB as Tier A 8; targets rewritten as reachable bands | §5.3, §1.4 |
| C3 | Crit | External/forced paths unattributable and unmeasured | Pre-harvest cache (admin/user stores, Rule T); R-ext and R-force runs with gates | §6.2, §1.3, §10.2 |
| C4 | Major | Path references in value names unspecified | Reference index over names, data, MULTI_SZ segments and REG_BINARY UTF-16; Firefox golden tests | §5.5 |
| C5 | Major | No catch-all scanner; exe- and AUMID-keyed locations | REF-ANY (v1), REG-EXEKEYED, CLS-AUMID, CLS-TOASTS, CLS-AUTOPLAY, COM-MEDIA, REG-OFFICEADDIN, REG-BROWSEREXT | §5.6 |
| C6 | Major | Harvest misses co-removed and Burn child products; Package Cache roots | Children and siblings harvested; co-removed products attached; never infer a root under Package Cache or `%WINDIR%` | §5.2, §6.1 |
| C7 | Major | Key-level MSI blocker hides target subkeys; `%WINDIR%` targets block launcher cleanup | Row-granular ownership; `MicrosoftSystemTarget` narrowed; harvested-exe-set dangling references allowed | §5.3 |
| C8 | Major | `%APPDATA%\<Product>` hidden in Weak; metric rewards hiding | `ExactFullName` at least Likely; `recall_visible` gate; `recall_listed` informational | §5.3, §1.3 |
| C9 | Major | Opaque per-install tokens unused | `HarvestedToken` | §5.3 |
| C10 | Major | PATH segments outside the root | REG-ENV attributes via MSI Environment, Inno log and remembered manifest; unexpanded comparison | §5.6 |
| C11 | Major | Corpus types without scanners (ClickOnce, InstallScript, Tailscale, electron-builder, winget portable, portable entry) | X-CLICKONCE, `.appref-ms`, setup.ilg claim dropped, SYS-NETWORK report-only, Obsidian and winget portable added, FS-DANGLINGLINKS, `scan {path\|exe}` | §5.6, §10.4, §3.3 |
| C12 | Major | Contaminated truth; Defender keys; Notepad++ sparse | No numbers frozen until the M0 re-run; traps for Mozilla NMH and ShimInclusionList; Notepad++ sparse target | §1.3, §1.4, §10.2 |
| C13 | Major | Micro-averaged recall dominated by VS Code | Macro per app, per kind, per path; per-scanner reporting | §1.3 |
| C14 | Major | Shipped packs inactive until user approval | Shipped packs active by default (the pipeline approves) | §5.9 |
| Minor | — | Dotfiles; per-user Package Cache and desktop.ini; BCU parity ports scheduled too late; shortcut arguments and AUMIDs | FS-DOTFILES; both cache roots, desktop.ini treated as empty; MuiCache, Tracing, EventLog and WER moved to M1b; RAWPATH + arguments + AUMID parsing | §5.6, §5.10, §11.1 |

**Launch/UI review**

| # | Sev | Issue | Resolution | Where |
|---|---|---|---|---|
| U1 | Major | Gate calibrated on a bare window and the wrong flavour (slim = 280 ms) | Gate relative to a bare control (+60 ms) with an absolute guard; S1 skeleton bench; first frame trimmed; flavour recorded | §1.3, §9.2 |
| U2 | Major | "First frame" was really the first Rendering tick; ItemsSource timing | Marker renamed; presented-frame marker; ItemsSource set before Activate; names-visible is the primary gate | §9.2 |
| U3 | Major | Bimodal first launch after install ignored | First-launch metric (≤ 1.2 s); signing; unchanged-DLL reuse | §1.3, §7.9, §9.2 |
| U4 | Major | VM cold launch measures WARP | VM is functional only; bare-metal cold protocol plus an iGPU laptop | §1.3, §9.2 |
| U5 | Major | Broker can't reuse the medium engine's warm index | Medium engine only warms the page cache; broker indexes on start; elevation on the Uninstall click; harvest-complete metric | §3.1, §5.5, §1.3 |
| U6 | Major | All-users MSI enumeration fails unelevated; enrichment cost | `szUserSid=NULL` at medium; raw ARP first, then `programs.patch` | §3.3, §4.1 |
| U7 | Major | ShellExecuteEx threading, owner and cancel | STA thread, flags, hwnd, 1223 mapping, PID + ctime check | §3.1 |
| U8 | Major | "Always start elevated" costs launch time and breaks identity | Check in the custom Main before XAML; direct broker mode; shell-owner identity; warning | §3.1 |
| U9 | Major | HMAC protects nothing; 10-min broker idle | HMAC dropped; own-plans-only; fresh prompt for irreversible verbs; broker exits after execute | §3.1 |
| Minor | — | OptimizeApplyStyles; generated Main; PNG icons; WinAppSDK 2.x EOS; TreeView | OptimizeApplyStyles off; custom Main + CreateProcessW; BGRA batches, gate on warm cache; scheduled upgrade; flattened ListView + 2k bench | §9.1, §9.2, §9.4 |

**Feasibility review**

| # | Sev | Issue | Resolution | Where |
|---|---|---|---|---|
| F1 | Crit | Rig cannot score the v1 scanners | Same as C1, plus values parsed from the existing `reg export` and Target-granular scoring | §10.2 |
| F2 | Crit | `programs.rs` is UT-derived; M1 gated on clone parity | Nothing taken from `programs.rs`; inventory written fresh; M1a exit against the raw enumeration; InstallProperties test dropped; trace::compare dropped | §4.2, §11.1 |
| F3 | Major | Milestone order (UI before engine) | Engine dry run first (M1a/M1b), executor M2, UI + broker M3 | §0 D8, §11.1 |
| F4 | Major | M3 depended on the M4 runner; no CLI; monolithic gate | CLI contract; minimal runner in M1a; engine split into M1a/M1b with their own gates | §3.4, §11.1 |
| F5 | Major | UIPI/HMAC false | Same as S4 / U9 | §3.1 |
| F6 | Major | LTSC baseline used on a Pro host | Baselines keyed by (edition, build); Clean-Pro VM; values-only + X-SYSTIDY without a match | §5.7.1, §10.2 |
| F7 | Major | `snap0` guard corpus unbuildable and contaminated | Old snap0 discarded; property moved to a rig check; compact baseline filter from clean VMs | §10.1, §10.2 |
| F8 | Major | Language split unjustified | Decision record D1 (Rust kept, with reasons, NJsonSchema for DTOs, revisit trigger) | §3.5 |
| F9 | Major | `undo_fidelity` unachievable as defined | Field-level definition with stated exclusions | §10.3 |
| Minor | — | Warm-scan metric; KB lifecycle before the agent; trap engineering in M2; client token access; Apache notice; Chocolatey scope; helper names; arm64/MCP pinning; Program Files installer; S3 mockup evidence | Targeted scan + cold-broker metric; lifecycle moved to M6; PowerShell traps in M2, installer traps in M4; ImpersonateNamedPipeClient; copyright line kept; Chocolatey limited to the community repo; Job object primary, names from BCU/docs; x64 only, MCP unpinned until M6; `install.ps1`; S3 redrawn with v1 evidence only | §1.3, §5.9, §10.2, §3.1, §11.4, §4.2, §0, §7.9, §9.4 |

**Rejected or partly adopted**

| Item | Decision |
|---|---|
| F8, the C# engine alternative | Evaluated and **rejected for now**, with an explicit revisit trigger (§3.5). |
| C2, "treat any VM-validated KB rule as Tier A" | Adopted **only** for shipped packs whose match is anchored to a harvested Tier A fact from the same session. Local and agent packs stay Tier B, as the safety review required. |
| C3, a pre-harvest cache in `%LOCALAPPDATA%` as Tier A for everything | Adopted with Rule T: the user store is Tier A only for per-user targets. Machine-scope Tier A requires the admin store. This resolves the conflict with safety finding S20. |
| S4, "relaunch the review screen elevated" | Not adopted. Only the final consent moves to the broker, which keeps the main UI medium-IL (drag and drop, launch time). |

**M2 deviations (recorded at M2-POSTM1A)**

Where the M2 executor departs from the text above. Each row states what M2 does and why; the sections above are not rewritten.

| # | Sev | Issue | Resolution | Where |
|---|---|---|---|---|
| M2-1 | Major | §7.1 hashes "the canonical plan JSON", but the plan document (`purge.plan/0`) is the rig's scoring format: it lists the top-level items only, without absorbed children, evidence or scan-time facts, which the executor needs | The executor's input is the scan document (`purge.scan/0`, the sidecar written next to the plan), which carries the full top-level and absorbed candidates. The executor recomputes the plan hash from those candidates and refuses when it differs from the stored one, so the hash still binds what runs; the plan document stays the rig's format | §7.1, `purge-plan::emit`, `purge-exec::plan_in` |
| M2-2 | Major | "Consent" was not specified as data, so a selection made after the hash was shown was not bound | `confirm = SHA-256(hex(plan_hash) ‖ hex(selection_hash))`, where `selection_hash` is the SHA-256 of the selected ids (de-duplicated, sorted by UTF-16 code unit, joined with `\n`). The default selection is every item in band Safe that the plan preselected; an explicit selection may add Likely and Weak items and needs its own confirm value | §7.1, §3.4, `purge-exec::plan_in` |
| M2-3 | Major | §7.2 asks for G1 (canonical path, final path, FileId) at plan time and before each item, but a plan hash that includes a FileId would change every M1a hash and every golden | The identity check is (a) the start-of-run validate pass, which re-reads every selected item before anything is changed, plus (b) an optional scan-time identity, `Candidate::item_fp` (FileId and volume serial of each path item, read by handle without following reparse points). `item_fp` is not part of the plan hash; it can only make the executor refuse or skip an item, never act on more. When it is absent (plans from before M2, or a path that could not be read) the validate pass alone applies | §7.2 G1, `purge-model::candidate`, `purge-plan::hash` |
| M2-4 | Major | §7.1 orders tasks, firewall rules and service deletes, and §7.4 asks for full definitions, but no M1a scanner emits those targets | The plan order now has the §7.1 stages for them (tasks and firewall rules before registry values, service deletes after files), so a later plan is ordered correctly without a hash change. Their execution, backup and undo are deferred to M1b, with the scanners that emit them. Until then such an item may be selected but has no executor op and is journalled as skipped | §7.1, §7.4, `purge-plan::order` |
| M2-5 | Minor | §7.1 lists shell/COM, shortcuts and the prune step as stages of their own | Not split out in M2: doing so would reorder M1a plans and change their hashes. Shell/COM keys and values are ordered with the other registry items, shortcuts with the other files, and empty parents are pruned by the delete-if-empty items in their deepest-first place | §7.1, `purge-plan::order` |
| M2-6 | Minor | §7.8 asks for typed undo per action | Typed actions are AppX only in M2 (`RemovePackage`), which is irreversible and never preselected; service, task and firewall inverses arrive with M1b. Files and registry undo through quarantine and the JSON registry backup | §7.8, `purge-exec::act_typed` |
| M2-7 | Minor | The Win32 value reads (`RegEnumValueW`, `RegQueryValueExW`) zero the last byte of string data of odd length, so the scan could report bytes that are not stored, and a backup taken from such a read would not restore them | Values are read with `NtEnumerateValueKey` and `NtQueryValueKey`, which report exactly the stored bytes. Well-formed data reads the same either way, so no scan output for it changes | §7.4, `purge-win::reg` |