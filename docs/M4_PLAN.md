# M4 plan: coverage, forced and external removal, knowledge packs

Written 2026-11-28 on `ui/rust` at `348b861`. Sources: `docs/ENGINE_PLAN.md` (§3.3, §3.4, §4.4, §5, §6.2, §9
S5 and S7, §10.2, §11.1), `docs/M3_DESIGN.md` (5.2, 7, 7a, 15, 17), `docs/UI_RUST_PLAN.md`, `docs/DECISIONS.md`
and the code as it stands.

## 0. The frame (user decision 2026-11-28)

- **1.0 = M4 + M5 (ETW observation) + M6 (AI agent) + their UI.** Features and UI first. This replaces the
  DECISIONS row of 2026-11-22 ("v1 ships after M4").
- **VM gates and corpus tests are deferred until after 1.0**, except one VM run of the UI when everything is
  implemented. Section 6 lists every deferred check so that none is lost.
- **Per-change checks:** unit tests, clippy, and the scripted walk on the hidden desktop.
- **Nothing destructive on the dev PC.** Real uninstalls, forced removals, `plan.execute` and anything that needs
  the elevated broker run only in the VM. On the PC the window runs with `--sample`, and the engine runs read-only.
- **Releases** are `0.2.0-beta.N`, one whenever a user-visible package set is merged (section 4.4). This replaces
  the beta rule in `docs/HANDOFF-ui-rust.md`.
- **Who does what:** Opus agents implement, at most 3 at once, each in its own worktree branched from `ui/rust`.
  Fable writes this design and reviews the milestone, and reviews the packages marked **Fable review** before
  they merge.

## 1. What is already built

Nothing below is planned again. The packages of section 4 start from it.

| M4 piece (ENGINE_PLAN) | State on `ui/rust` | Where |
|---|---|---|
| The three scan modes in the model, the policy and the plan | **Built.** `ScanMode::{Post, External, Forced}`; the policy's mode rules (forced: nothing Safe or preselected; external: Safe only on admin-only evidence scoring 8 or more); the mode is part of the plan hash | `purge-model/src/plan.rs`, `purge-policy/src/band.rs` (rule 6), `purge-plan/src/{decide,hash,empty_after}.rs` |
| Forced scan after a failed or unverified uninstall | **Built, engine and UI.** The broker picks `Forced` unless its own uninstaller ran, succeeded and verify-gone passed; the client can lower the mode (`forced: true`), never raise it. The Uninstall page offers "Run forced cleanup"; the Leftovers page shows "Nothing is ticked for you." | `purge-broker/src/scan.rs`, `uninstall.rs`; `purge-ui-model/src/pipeline/uninstall.rs`, `leftovers/text.rs` |
| Forced removal of a program **without running** its uninstaller | **Engine half built, no entry.** A prepared session that never ran scans `Forced`. But `uninstall.prepare` fails with "has no uninstall command" when the entry has none, and no UI path skips the uninstaller | `purge-broker/src/uninstall.rs:628` |
| Forced removal of a folder (portable app) | **CLI only.** `pipeline::scan_path` ("minimal M1a implementation") behind `purge-engine scan --path`. The broker has no path scan, the UI no entry, and `ProgramId` has only the ARP form | `purge-engine/src/pipeline.rs:1859` |
| External mode for a program removed outside Purge | **Built for programs the broker once prepared.** `inventory.changes` and `inventory.forget` (medium), `leftovers.stored`, `leftovers.scan {program_id}` from the stored fingerprint (`External`, verify-gone afresh), the "Removed outside Purge" group with "Check for leftovers" and "Dismiss" | `purge-engine/src/stdio.rs`, `purge-broker/src/scan.rs`, `purge-client/src/fingerprint.rs`, `purge-ui-model/src/pipeline/removed.rs` |
| Pre-harvest cache (§6.2) | **Not built.** A fingerprint is stored only by `uninstall.prepare`, so a program Purge never tried to uninstall has no record | — |
| Scanners | **33 built** (M1a 19, M1b 14). Every M4 row of §5.6 is missing (section 4, SCAN packages). The guard's single-file `Prefetch` exemption exists already | `purge-scan/src/catalog.rs`, `purge-guard/src/deny.rs` |
| Knowledge packs | **Not built.** `purge-kb` is a doc comment, `kb/packs` is empty, there is no `KnowledgeRule` evidence kind. The CLI already parses `kb lint` | `crates/purge-kb`, `kb/packs/README.md` |
| Other profiles | **Not built, and one protective half is missing too:** the profile list is used for names and roots, but unloaded profiles' hives are never read, so a per-user program of a user who is not logged on is not in the ownership index (§4.1 and §5.3 say it is) | `purge-harvest/src/{harvest,roots}.rs`; `purge-win/src/offreg.rs` is used by the local baseline only |
| S5 Settings | **Reduced page.** Look, theme, transition, backdrop, the stated ticking rule, retention with "Open quarantine", About. The S5 choices were hidden on 2026-11-24 because they changed nothing | `purge-ui/src/screens/settings.rs`, `prefs.rs` |
| Leftover groups | **Built**, by category: Files & folders, Registry, File associations & protocols, Shell & COM, Services, tasks & other, Packages, Privacy traces, plus the Protected and Report-only sections. New scanners land in them through their `Category` with no UI change | `purge-ui-model/src/leftovers/{item,text}.rs` |

Two consequences for ENGINE_PLAN's evidence table: **`RememberedManifest` is not added.** The stored fingerprint
*is* the harvest, written by the broker into the admin-only store, so an external scan has the ordinary evidence
kinds at their recorded trust and the external-mode rule of the policy applies as it stands. And **`Traced`**
stays for M5.

## 2. What M4 means for the user

Ids are AutomationIds. The conventions of `docs/UI_RUST_PLAN.md` hold: an open dialog is one node `ContentDialog`
with `DialogTitle`, `DialogText`, `DialogPrimaryButton`, `DialogSecondaryButton`, `DialogCloseButton`; a bar is
`InfoBarHost` (`InfoBarHost_n`) named "Title Message"; a Text's name is its whole text. Every new id is added to
the AutomationIds section of `docs/UI_RUST_PLAN.md` by the package that makes it.

### F1. Force remove a listed program (S7 "Force remove", S2 error bars)

For a program whose uninstaller is missing or broken, or that the user wants gone without running it.

- **Programs page, details pane:** `DForceRemoveButton` "Force remove…", next to `DUninstallButton`. When the
  entry has no uninstall command or its uninstaller file is gone, `DUninstallButton` is disabled with the reason
  as its description ("No uninstaller is registered." / "Its uninstaller is missing.") and the pane shows
  `DNoUninstallerText` with the same sentence.
- **Dialog:** `DialogTitle` "Force remove <name>?"; `DialogText` says what happens (Purge records what the
  program registered, does not run its uninstaller, and lists what it finds with nothing ticked); the mandatory
  tick box `ForceUnderstandBox` "I understand that this skips the program's own uninstaller and that nothing
  will be ticked for me"; `DialogPrimaryButton` "Force remove" stays disabled until the box is ticked and
  `ARM_DELAY` has passed; `DialogCloseButton` "Not now".
- **Uninstall page:** the same stepper (`StepperHost`); step 2 reads "Uninstaller not run (forced removal)" and
  is shown as skipped, never as failed. The Windows prompt and the first-elevation explanation are as for an
  uninstall.
- **Leftovers page:** the existing forced bar with a text of its own for this entry ("You chose a forced
  removal, so nothing is ticked for you."), mode line "Forced scan". When the program is still registered with
  Windows Installer, a second bar says so ("Windows Installer still lists <name>; its registration is kept. Use
  Uninstall to remove it."): those rows are Protected by `MsiProductStillRegistered`.
- **"Remove entry" (S7) is not a feature of its own.** In a forced scan the program's own Uninstall key is a
  candidate (`UninstallerArtifact`), unticked; ticking it is "Remove entry", backed up and undoable like the rest.

### F2. Force remove a folder (portable app; `scan --path`)

- **Programs toolbar:** `ForceFolderButton` "Force remove a folder…" (also a palette entry).
- **Dialog:** `DialogTitle` "Force remove a folder"; `ForcePathField` (a whole text field, AGENTS.md rule 2, with
  the app's edit-menu words); `ForceBrowseButton` "Browse…" only if the toolkit has a folder dialog at the pin
  (else a row in `docs/TOOLKIT_REQUESTS.md`, and the field alone ships); `ForcePathError` under the field for a
  refusal, in the broker's words ("This folder belongs to <program>, which is installed. Use Uninstall.", "This
  is a Windows folder.", "A folder inside Documents cannot be force removed."); `ForceUnderstandBox` and the
  buttons as in F1.
- Then the Windows prompt, the Uninstall page with the two steps "Reading the folder" and "Finding leftovers",
  and the Leftovers page in the forced mode. The folder itself is one unticked row.

### F3. Programs removed outside Purge (external mode, §5.1, §6.2)

- **Recording.** A new Settings card `CardRecords` "Programs Purge has recorded": `RecordStateText` ("142 of 151
  programs recorded · last on 28 Nov"), `RecordNowButton` "Record now" (the Windows prompt; then
  `RecordProgressText` "Recording 37 of 151: <name>" and `RecordCancelButton`), and `RecordAutoSwitch` "Also
  record whenever Purge already has administrator permission" (on by default; the broker records in the
  background while it is open for something else).
- **Programs page:** once per install, a bar "Purge can find leftovers of a program removed outside it only if
  it recorded the program first." with `BarButton` "Record now". The existing `RemovedGroup` rows keep "Check for
  leftovers" and "Dismiss"; with the cache most rows now have a record.
- **A removed program with no record:** the row says "No record: Purge can only look by name" and offers
  `RemovedByNameButton` "Look by name" (package M4-EXT-NOFP). That scan runs under the forced rules.
- **Leftovers page:** mode line "External scan"; a bar "Removed outside Purge. This list comes from Purge's
  record of <date>."; fewer items are ticked than after a Purge uninstall, and each unticked Safe-looking row
  carries the policy's note ("Not ticked: … does not come from an administrator-only source").

### F4. More leftovers found (the M4 scanners)

No new page. The new items appear in the existing groups:

| Group | New in M4 |
|---|---|
| Registry | exe-keyed settings (IE feature control, media shim list, elevation policy, drag-drop policy, game config, DirectInput), notification settings, Active Setup, native messaging hosts, Office add-ins, browser extension registrations |
| Shell & COM | AutoPlay handlers, DirectShow and Media Foundation registrations, the remaining shell-extension handler kinds |
| Files & folders | installer scratch in `%TEMP%`, dotfolders of the app in the profile (user data, unticked), Squirrel and electron-updater folders |
| Privacy traces | Prefetch traces, FeatureUsage |
| Services, tasks & other | event publishers, heap-leak and audio-policy records |
| Report only | dangling links in PATH folders and `WinGet\Links`, `Windows\Installer\{code}` icon folders, Defender exclusions, network profiles, the ClickOnce store |
| New group **Tidy-up** (`Tidy-up`, unticked, collapsed, opt-in) | empty skeleton keys nobody claims (X-SYSTIDY) |

Until the corpus gate has run (section 6), every item of a new scanner is at most Likely, so **unticked**; its
detail pane says "Not ticked: this kind of leftover is new in this version" (section 5, I5).

### F5. Other users' leftovers, read-only

- **Setting** `PrefOtherProfilesSwitch` "Also look in other users' profiles (shown only, never removed)", off by
  default.
- **Leftovers page:** a section **Other users** (`is_section`, no tick boxes) listing per user what the program
  left in that profile. The rows cannot be ticked; the detail pane says "In <user>'s profile. Purge does not
  change other users' files; that user can remove it by running Purge."
- **Always on, without a setting:** a program installed for another user protects its files and registrations
  ("Kept: still used by <program> (installed for <user>)"), also when that user is not logged on.

### F6. Knowledge packs (§5.9)

- Purge knows named leftovers of common programs (first packs: Mozilla Firefox / Thunderbird / Maintenance
  Service, VS Code and Insiders, Git, Python and the Launcher relation, WinMerge, Notepad++, 7-Zip): rows it could
  not attribute before now appear, with the why-line "knowledge pack <id> v<n>". Packs also **protect**: known
  user-data folders (`Notepad++\backup`, `Code\User`, Firefox `Profiles`) are marked user data and stay unticked.
- A pack never ticks anything in M4 (section 5, I6).
- **Settings card** `CardPacks` "Knowledge packs": `KbPackList`, one row per shipped pack with its version and the
  programs it covers. Read-only: no per-pack switch in M4.
- **"Always keep"** (S3): in the Leftovers detail pane, `KeepAlwaysButton` "Always keep this". The row becomes
  "Kept by your rule", unticked and not tickable. Settings card `CardKeep` "Always keep": `KeepRuleList` with a
  `KeepRuleRemove_n` per rule.

### F7. Settings that do something (S5)

Each comes back only wired (DECISIONS 2026-11-24, "nothing on screen may pretend"), saved in
`%LOCALAPPDATA%\Purge\ui-settings.ini`:

| S5 row | M4 | Id |
|---|---|---|
| Prefer quiet uninstall | The start value of `QuietSwitch` in the confirm dialog | `PrefQuietSwitch` |
| Restore point: Off / High-risk only / Always | The start value of `RestorePointBox` | `PrefRestorePoint` |
| After uninstalling: Scan for leftovers / Ask | Ask shows the result of the uninstall with "Find leftovers" instead of scanning at once | `PrefAfterUninstall` |
| Show weak matches | The start state of the Leftovers page's own button | `PrefWeakSwitch` |
| Include other user profiles | F5 | `PrefOtherProfilesSwitch` |
| Knowledge packs; "Always keep" rules | F6 | `CardPacks`, `CardKeep` |
| Recorded programs | F3 | `CardRecords` |
| About: baselines available | One more line from `engine.hello` | `AboutBaselineText` |
| Quarantine: "Empty quarantine…" | On the Quarantine page: `EmptyQuarantineButton`, one `quarantine.purge` of everything through the broker's purge dialog, which names the size and that it cannot be undone | `EmptyQuarantineButton` |

Not built, and why: "Pre-select user data" (it would break `userdata_preselected = 0`), "Pre-select app caches"
(preselection is the broker's rule, not a setting), "Close running apps without asking" (report-only since M3,
answer 5), the AI card (M6), "Always start as administrator" and "Compact rows" (section 6).

## 3. Contracts

### 3.1 RPC (`purge-rpc`; package M4-RPC lands all of it first)

Wire types live in `purge_rpc::methods` only, each with a fixture in `crates/purge-rpc/fixtures` and its schema
test. All additions are optional fields or new forms, so an older fixture still parses.

| Change | Form | Served | Notes |
|---|---|---|---|
| `Prepared.uninstaller` | `"present"` (default) \| `"no_command"` \| `"file_missing"` | pipe | With the last two, `command` is empty and `uninstall.run` of the session is refused with a runtime error ("nothing to run"). `uninstall.prepare` no longer fails for such an entry |
| `leftovers.scan`, third form | `{path: String, other_profiles?: bool}` (`ScanPathParams`) | pipe, Read, cancellable | Always `Forced`. A refused folder answers a runtime error whose `data` names the reason code (`deny_listed`, `other_app {name}`, `known_folder`, `not_a_folder`, `not_canonical`) |
| `leftovers.scan`, all forms | `other_profiles: bool`, default false | pipe | Adds report-only rows only |
| `ScanResult.app_name` | `Option<String>` | pipe | The name the broker's fingerprint gives; the Leftovers title of a folder scan |
| `fingerprints.refresh` ⇢ `refresh.progress` | params `{program_ids?: [ProgramId]}`; result `{recorded, unchanged, failed: [{program, reason}], removed, cancelled}` | pipe, Execute, cancellable, no consent | Writes only into Purge's own store. Program ids are resolved against the broker's own inventory; nothing else comes from the client |
| `fingerprints.state` | result `{programs: u32, recorded: u32, last: Option<time>}` | pipe, Read | For `RecordStateText` after a run; the medium UI otherwise only knows file names (`purge-client/src/fingerprint.rs`) |
| `kb.list` | result `{packs: [{id, version, title, programs: [String]}]}` | stdio, Read | Packs are compiled in, so the medium engine can list them |
| Row marks | warning codes on `CandidateRow.warnings`: `ReportOnly`, `OtherProfile`, `NewScanner`, `KbPack` | pipe | No new DTO field. `purge-ui-model` already sorts rows into the Report-only section by a code containing `reportonly`, **but the broker sends no such code today** (its row warnings are blocker names only), so a report-only candidate shows as an ordinary row that `plan.create` then refuses. M4-RPC makes `scan::row` add `ReportOnly` for `Action::ReportOnly`; the other three are added by packages 2, 12 and 14 |

M4-RPC also adds the dispatcher arms in both servers as stubs that answer a runtime error "not available yet",
each in the file its later package fills (`purge-broker/src/refresh.rs`, the path arm in `scan.rs`,
`purge-engine/src/stdio/kb.rs`), and the sample answers in `purge-client/src/sample.rs` and
`purge-ui/src/sample_broker.rs`, so UI packages can start against `--sample` at once.

**One writer per wave:** after M4-RPC, a package changes `methods.rs` or `table.rs` only if section 4 says so
(M4-EXT-NOFP alone).

### 3.2 Model and policy (package M4-POLICY)

- `EvidenceKind::KnowledgeRule` with its tier, weight and scope data in `purge-model/src/evidence.rs` (Tier B,
  weight 4, scope as the rule declares; the anchored Tier A row of §5.3 is **not** enabled, I6).
- `Blocker::OtherProfile { user }` (hard): the candidate lies in another user's profile or hive.
- `Blocker::NewScanner` is **not** a blocker; the cap is a policy rule: a candidate whose `scanner` is in
  `purge_policy::band::UNVALIDATED_SCANNERS` is at most Likely and never preselected, with
  `Note::ScannerNotValidated`. The list holds every scanner id added in M4; a scanner leaves it only after the
  corpus gate.
- `POLICY_VERSION` becomes `m4.1`. Golden files that carry the version are regenerated in the same commit; no
  other golden may change.
- `ProgramId`: M4-FORCE-ENGINE adds what a folder scan needs (a second id form, or `Scan.program` optional).
  Whichever it is, a folder scan never writes a fingerprint to the store and never matches a stored one.

### 3.3 Scanner contract (every SCAN package)

- One file per scanner in `crates/purge-scan/src/<id>.rs` implementing `framework::Scanner`; a test target under
  `crates/purge-scan/tests/<area>/` with a `world.rs` built like `tests/privacy/world.rs`.
- **Catalog order is fixed here** so that parallel packages merge the same way. Append to `SCANNER_IDS` and
  `all_scanners` after the M1b block, under a `// M4.` comment, in this order: `REG-EXEKEYED`, `REG-NOTIFY`,
  `REG-ACTIVESETUP`, `REG-NMH`, `REG-OFFICEADDIN`, `REG-BROWSEREXT`, `CLS-AUTOPLAY`, `COM-MEDIA`, `FS-PREFETCH`,
  `FS-TEMP`, `FS-DOTFILES`, `FS-DANGLINGLINKS`, `FS-INSTALLERICONS`, `SYS-DEFENDER`, `SYS-NETWORK`, `X-SQUIRREL`,
  `X-CLICKONCE`, `X-KB`, `X-SYSTIDY`. Extensions of existing scanners (REG-PRIVACY, REG-DIAG, COM-SHELLEX) stay in
  their files. A merge conflict in `catalog.rs` or `lib.rs` is resolved by keeping both sides in this order.
- Value-level scanners declare `value_containers()`, and the same keys go into
  `purge_guard::containers` as a new table `M4_VALUE_CONTAINERS` (the equality test in `purge-scan` and
  `xtask scanner-coverage` compare them).
- No scanner walks the registry (`xtask no-new-walks`): read the hits of the one reference walk, or read named
  keys.
- **Rig roots:** a location the rig does not capture yet goes into a new list `M4_PENDING_ROOTS` in
  `tools/xtask/src/scanner_coverage.rs` (root, scanner, why). The check accepts a pending root only for a scanner
  in `UNVALIDATED_SCANNERS`. Nothing under `vm/` is edited.
- **No new executor operation.** M4 scanners use the existing pairs (`Quarantine` of a path, `DeleteKey`,
  `DeleteValue`, `EditSegment`, `RemoveDirIfEmpty`) or `ReportOnly`. Anything that would need a new op (a Defender
  exclusion, deleting a reparse point) is `ReportOnly` in M4 (I7).

### 3.4 UI contract

- `purge-ui-model` models stay plain state machines over `purge_rpc` values; `purge-ui` draws and wires. The
  "not available yet" rule: a control whose engine side is not merged yet is **absent**, not disabled, and a page
  that cannot work with the real engine says "not available yet in this version"; never a silent no-op.
- Every new flow gets steps in `bins/purge-ui/src/script_steps.rs` (the `--sample --script` walk) and its ids in
  `vm/guest/tests/ui-a11y-probe.ps1` (a host-side UIA probe; run it on the hidden desktop, never in a VM).
- AGENTS.md holds: text fields wired whole, every held press let go on `Focus(false)` and `PressLost`, the edit
  menu in the app's words, the toolkit never changed from this repository (gaps go to
  `docs/TOOLKIT_REQUESTS.md`).

## 4. Packages

Sizes are one agent session each. **Deps** must be merged into `ui/rust` before the package starts. A free slot
takes the next package in the order below whose deps are merged. Files in **bold** are owned by that package for
its wave: no other running package edits them.

### 4.1 Order and waves

| # | Package | Deps | Fable review | Wave |
|---|---|---|---|---|
| 1 | M4-RPC | — | — | 0 |
| 2 | M4-POLICY | — | **yes** | 0 |
| 3 | M4-KB-CORE | — | — | 0 |
| 4 | M4-FORCE-ENGINE | 1 | **yes** | 1 |
| 5 | M4-FORCE-UI | 1 | — | 1 |
| 6 | M4-PREHARVEST | 1 | **yes** | 1 |
| 7 | M4-EXT-UI | 1 (works on sample before 6) | — | 2 |
| 8 | M4-SCAN-REG1 | 2 | — | 2 |
| 9 | M4-SCAN-FS | 2 | — | 2 |
| 10 | M4-SCAN-REG2 | 2, 8 | — | 3 |
| 11 | M4-SCAN-COM | 2 | — | 3 |
| 12 | M4-KB-MATCH | 2, 3 | **yes** | 3 |
| 13 | M4-SCAN-X | 2, 9 | — | 4 |
| 14 | M4-PROFILES | 1, 2 | **yes** | 4 |
| 15 | M4-SETTINGS | 5, 7 | — | 4 |
| 16 | M4-LEFTOVERS-UI | 12, 14, 15 | — | 5 |
| 17 | M4-TRAPS | 8 to 13 | — | 5 |
| 18 | M4-EXT-NOFP | 6, 7 | **yes** | 5 |

Then the milestone review (Fable, over the whole diff against `348b861`) and its fix round.

### 4.2 The packages

**1. M4-RPC** — the wire contract of 3.1.
- Files: **`crates/purge-rpc/src/{methods,table}.rs`**, `crates/purge-rpc/fixtures/*`, `crates/purge-client/src/{lib,sample}.rs`,
  `bins/purge-ui/src/sample_broker.rs`, stub arms in `bins/purge-broker/src/{serve,scan}.rs`, new
  `bins/purge-broker/src/refresh.rs`, new `bins/purge-engine/src/stdio/kb.rs`.
- Tests: a fixture round trip and a schema test per new type; `lookup` answers `-32601` for `fingerprints.refresh`
  on stdio and for `kb.list` on the pipe; the three `leftovers.scan` forms decode apart, and an object carrying two
  of `session_id`, `program_id`, `path` is refused; old fixtures still parse; a candidate with `Action::ReportOnly` gets the `ReportOnly` row mark and lands in the UI model's Report-only section (a test on each side); each stub answers "not available
  yet"; `xtask check-deps` unchanged.

**2. M4-POLICY** — the model and policy additions of 3.2. *Fable review.*
- Files: **`crates/purge-model/src/{evidence,blocker}.rs`**, **`crates/purge-policy/src/{band,explain,score}.rs`**,
  `crates/purge-policy/tests/m4_bands.rs` (new), `crates/purge-plan/src/decide.rs` (tests only unless a rule needs it).
- Tests: for every scanner id in `UNVALIDATED_SCANNERS` and every mode, a Tier A candidate scoring 10 is Likely and
  not preselected; the same candidate from an M1 scanner is still Safe (no regression). `OtherProfile` gives
  Blocked in every mode and `plan::decide` never emits it into a plan. `KnowledgeRule` alone never reaches Safe;
  with real Tier A evidence beside it the band is what the Tier A evidence gives, no higher. Forced mode: a
  property test over generated candidates (any evidence mix, any scanner) finds none Safe and none preselected.
  External: a `UserWritable` Tier A set is never Safe. The golden plan-hash tests pass with only the version
  string changed.

**3. M4-KB-CORE** — the pack format, loader and lint (§5.9), no matching yet.
- Files: **`crates/purge-kb/**`**, `kb/packs/README.md`, `bins/purge-engine/src/cli.rs` (the `kb lint` verb's body).
- Contract: `purge_kb::{Pack, PackSet, LintError}`; `PackSet::shipped()` parses packs compiled in with
  `include_str!` (as `purge_identity::kbdata` does); `Pack` has `id`, `version`, `title`, `match`,
  `vendor_aliases`, `leftovers`, `parent_if_empty`, `protect`, `user_data`, `file_assoc`, `max_weight`.
  `lint(pack, &DenyList)` rejects: a template that resolves into a deny rule or a secrets store, more than one
  wildcard segment or a wildcard above depth 2, a location token outside the whitelist, a `leftovers` rule
  naming one of the blocked dotfiles, an unknown field. `purge-kb` depends on `purge-model` and `purge-guard`
  only (no `purge-win`, no I/O beyond reading a given file for the CLI).
- Tests: one accepted and one rejected sample per lint rule; every file under `kb/packs` passes lint in a test (so
  a bad pack fails CI); a fuzz-style test that no accepted template can expand to a path the deny list refuses,
  over the deny rules of `kb/deny.json`.

**4. M4-FORCE-ENGINE** — F1 and F2 behind the broker. *Fable review.*
- Files: **`bins/purge-broker/src/{uninstall,scan,session}.rs`**, **`bins/purge-engine/src/pipeline.rs`** (`scan_path`
  and the commands of an entry), `crates/purge-model/src/ids.rs` if the id needs a form, broker tests
  (`flow_tests.rs`, `serve/tests.rs`).
- Does: `uninstall.prepare` harvests an entry with no command or a missing uninstaller file and reports
  `uninstaller`; `uninstall.run` and `uninstall.observed` of such a session are refused; its `leftovers.scan` is
  `Forced` whatever the client sends. `leftovers.scan {path}`: canonicalise, refuse by `validate_root` **before**
  any scan with the reason codes of 3.1, harvest the folder as `scan_path` does, scan `Forced`, keep the scan
  for `plan.create` like a stored-fingerprint scan (no uninstall session). `scan_path` loses its "minimal M1a"
  warning only when the tests below hold.
- Tests (fixtures through the broker's `testkit`, no elevation): a folder that is, contains or lies inside
  another installed program's root is refused with `other_app`; so is a volume root, `Program Files`, a known
  folder, a path under a sync root, `%WINDIR%`, Purge's own directories, a reparse point, an 8.3 or `..` form that
  canonicalises elsewhere. Every candidate of a path scan and of a no-command session is not Safe and not
  preselected, for a fixture rich in Tier A evidence. The folder row is offered once, unticked. A second scan of
  a spent program is still refused (M3-R2 S2). `plan.create` with the preselected form on a forced scan yields an
  empty plan. A path scan writes nothing into `fp`.

**5. M4-FORCE-UI** — F1 and F2 in the window.
- Files: **`crates/purge-ui-model/src/pipeline/**`**, **`crates/purge-ui-model/src/programs/{page,strings}.rs`**,
  **`bins/purge-ui/src/screens/{programs,pipeline}.rs`**, `bins/purge-ui/src/{link/flow.rs,app.rs,script_steps.rs}`,
  `crates/purge-ui-model/src/leftovers/text.rs` (the two bar texts only).
- Does: `ProgramCommand::ForceRemove` and `ForceFolder`; a `ForceController` beside `UninstallController`
  (requests: `Launch`, `Prepare`, `Scan {session_id, forced: true}` or `ScanPath {path}`, never `Run`); the two
  dialogs; the skipped step; the bars of F1.
- Tests: model tests that the force flow never emits `PipelineRequest::Run` or `RunUser`; that the primary
  button cannot fire before the box is ticked and the delay has passed; that a refusal reason reaches
  `ForcePathError` and no scan request follows; that a cancelled Windows prompt leaves the page as an uninstall's
  does. Script steps: open the dialog from the details pane, tick, confirm, reach the Leftovers page with zero
  ticked rows and the forced bar; the folder dialog with a refused sample path and an accepted one.

**6. M4-PREHARVEST** — the admin-store cache of §6.2. *Fable review.*
- Files: **`bins/purge-broker/src/refresh.rs`**, `bins/purge-broker/src/{store_caches,lifetime}.rs`,
  `bins/purge-engine/src/pipeline.rs` (a `harvest_many` over one shared walk; coordinate with package 4, which
  owns the file in the same wave: this package adds one new function at the end of the file and touches nothing
  else there), `crates/purge-harvest` only if the shared indexes need an opening.
- Does: `fingerprints.refresh` harvests every program of the broker's own inventory (machine scope and the
  caller's hive) with **one** reference walk shared by all of them (`HarvestOpts::shared`), at background
  priority, and writes each fingerprint the way `uninstall.prepare` does (the checked `fp` handle, temp name,
  replace). A sidecar `fp\index.json` holds per program a gate hash (the entry's values and key time, size and
  time of `unins*.dat`, the LocalPackage's path, size and time, the fingerprint schema version) so an unchanged
  program is skipped. Fingerprints of programs absent from the inventory for more than 90 days are removed, and
  the store is capped (report the measured size per program in the hand-back; propose the cap from it). Step 2,
  only if step 1 is done and tested: the automatic run, started by the broker itself when it has been idle for 5 s
  with a client attached, stopped at once when any request arrives.
- Tests: an unchanged inventory records nothing the second time; a changed entry is recorded again; a program in
  another user's hive is never harvested for the caller; a cancel between programs leaves every written file
  whole and the index consistent; a file in `fp` that fails the store's integrity check is not read; a stale
  record whose root now belongs to another installed program gives Blocked rows in an external scan, not Likely;
  the external scan of a program that is still installed is forced (verify-gone afresh). Timing, engine level and
  read-only on the laptop: one walk for N programs (assert the walk count), and the wall time for the host's
  inventory in the hand-back.

**7. M4-EXT-UI** — F3 in the window.
- Files: **`crates/purge-ui-model/src/pipeline/removed.rs`**, new `crates/purge-ui-model/src/records.rs`,
  **`bins/purge-ui/src/screens/settings.rs`** (the `CardRecords` card only; M4-SETTINGS takes the file over in wave
  4), `bins/purge-ui/src/link/pages2.rs`, `crates/purge-ui-model/src/leftovers/text.rs` (the external bar).
- Tests: the records model over a fake broker (progress, cancel, a failed program listed, the state line); the
  one-time bar shows once and never again after "Record now" or its close; a removed row with a record offers
  "Check for leftovers", one without says so. Script steps for the card and the bar on sample data.

**8. M4-SCAN-REG1** — `REG-EXEKEYED`, `REG-NOTIFY`.
- Files: `crates/purge-scan/src/{reg_exekeyed,reg_notify}.rs`, `tests/exekeyed/`, catalog lines,
  `purge-guard/src/containers.rs` (`M4_VALUE_CONTAINERS`, created here), `scanner_coverage.rs`
  (`M4_PENDING_ROOTS`, created here).
- Tests, besides the common list of 5.2: a `ShimInclusionList` or `FEATURE_*` key is never offered as a key;
  an exe name that another installed program also ships is not attributed (unique-name rule); `DirectInput\<EXE>*`
  and `GameConfigStore\Children` match by path into the roots, not by a bare name; a notification key of an AUMID
  whose package is still installed is not offered.

**9. M4-SCAN-FS** — `FS-PREFETCH`, `FS-TEMP`, `FS-DOTFILES`, `FS-DANGLINGLINKS`, `FS-INSTALLERICONS`.
- Files: `crates/purge-scan/src/fs_{prefetch,temp,dotfiles,danglinglinks,installericons}.rs`, `tests/fs_m4/`.
- Tests: only single `<EXE>-<8 hex>.pf` files, never the folder, and not for an exe name another program has;
  `FS-TEMP` offers nothing that is locked, outside the uninstall window, or not matching an installer pattern, and
  everything unticked; `FS-DOTFILES` never names `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`,
  `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.netrc` (one test per name, by exe-set name and by a
  made-up rule), and is always `UserData`; dangling links and installer icon folders are `ReportOnly` and the
  scanner never follows a link (the fixture's link target is a canary directory that must not be read).

**10. M4-SCAN-REG2** — `REG-ACTIVESETUP`, `REG-NMH`, `REG-OFFICEADDIN`, `REG-BROWSEREXT`, and the M4 rests of
`REG-PRIVACY` (FeatureUsage, `Search\JumplistData`) and `REG-DIAG` (`WINEVT\Publishers`, HeapLeakDetection, Audio
PolicyConfig).
- Tests: Defender's `Mozilla\NativeMessagingHosts` host is never offered, and the `NativeMessagingHosts` key
  itself never whole; a native-messaging manifest that points into the roots is attributed, one that points
  elsewhere is not; an Active Setup component whose StubPath is another program's is not offered; the extensions
  to REG-PRIVACY and REG-DIAG leave their M1b goldens unchanged.

**11. M4-SCAN-COM** — `CLS-AUTOPLAY`, `COM-MEDIA`, and the rest of `COM-SHELLEX` (DropHandler, IconHandler,
DataHandler, thumbnail, infotip and PropertyHandler, `.ext\PersistentHandler`, `Shell Extensions\Cached`,
`PropertySystem\PropertyHandlers`, `NameSpace`, `SyncRootManager`).
- Tests: a category key (`CLSID\{cat}\Instance`) is never offered, only the instance of an owned CLSID; a CLSID in
  `kb/shared-iids.json` or with another referrer is Blocked; a `SyncRootManager` entry is report-only when its
  sync root still exists; the COM-SHELLEX M1b goldens are unchanged.

**12. M4-KB-MATCH** — `X-KB`, the first packs, `kb.list`. *Fable review.*
- Files: `crates/purge-scan/src/x_kb.rs`, `tests/kb/`, **`kb/packs/*.json`**, `bins/purge-engine/src/stdio/kb.rs`,
  `bins/purge-engine/src/pipeline.rs` (handing the pack set to the scan context), `crates/purge-policy/src/explain.rs`
  (the why-line).
- Does: a pack applies only when its `match` holds for the fingerprint (ARP name, publisher, signer, installer
  kind); `leftovers` rules give candidates with `Origin::Signature` and `KnowledgeRule` (Tier B); `user_data` and
  `protect` rules mark or block candidates of **any** scanner; `vendor_aliases` feed the identity. Raising rules
  load only from the compiled-in set. Packs are written from the frozen truth data in the repository and the
  licence-clean sources of §5.9, never from Winapp2 or BleachBit.
- Tests: no pack rule yields Safe or a preselected row in any mode; a pack whose `match` fails adds nothing; a
  `user_data` rule turns an otherwise Safe cache candidate into unticked user data; `protect` blocks; the Mozilla
  rules attribute only the `updates\<hash>` of the harvested install hash and keep `profiles.ini` while a profile
  directory stays; the VS Code pack does not touch Insiders' folders and the other way round; every pack passes
  lint; `kb.list` matches the files.

**13. M4-SCAN-X** — `X-SQUIRREL`, `X-CLICKONCE`, `X-SYSTIDY`, `SYS-NETWORK`, `SYS-DEFENDER`.
- Tests: Squirrel's `Update.exe`, `packages\` and `SquirrelSetup.log` only under a root of the fingerprint, and
  an app named or installed into "Update" does not make every `Update` folder a match; the electron `appId` key
  only by harvested token; ClickOnce, network and Defender rows are `ReportOnly` (a Defender exclusion managed by
  policy says so); `X-SYSTIDY` rows are Weak or Likely, never ticked, only for keys that are empty, not in the
  baseline, not TrustedInstaller-owned and not structural.

**14. M4-PROFILES** — F5 and the missing protection. *Fable review.*
- Files: `crates/purge-source/src/{system,live/system,fixture}.rs` (a read-only view of another profile's hive:
  loaded through `HKU\<SID>`, unloaded through `purge-win` offreg), `crates/purge-index/src/ownership.rs`,
  `crates/purge-harvest/src/roots.rs`, `crates/purge-scan/src/framework.rs` and a new
  `crates/purge-scan/src/other_profiles.rs`, `bins/purge-broker/src/scan.rs` (the `other_profiles` flag).
- Does, in this order: (a) always: Uninstall entries of every other profile join the ownership index, so their
  roots and anchors block (`InsideOtherApp`, `ReferencedByOtherApp`). An unloaded hive is opened read-only, never
  loaded, never copied into a user-writable place, with no privilege raised; a hive that cannot be read gives a
  scan warning naming the user. (b) with the flag: per other profile, the app's AppData folders and `Software`
  keys by the same attribution as the interactive user's, as `ReportOnly` candidates with `Blocker::OtherProfile`.
- Tests: a root shared with another user's per-user install blocks the directory; an other-profile row can never
  be put in a plan (`plan.create` with its id is refused) and never has a tick; without the flag there are no
  such rows but the protection holds; a hive file that is a reparse point or is not owned as a profile hive
  should be is not opened; fixture with a second loaded hive (`SID2` of the test worlds) and one offline hive.

**15. M4-SETTINGS** — F7.
- Files: **`bins/purge-ui/src/screens/{settings,quarantine}.rs`**, **`bins/purge-ui/src/prefs.rs`**,
  `crates/purge-ui-model/src/{pipeline/uninstall.rs,vault/mod.rs}` (start values; the empty-all request).
- Tests: each preference round-trips through the settings file and a damaged value is the default; the start
  values reach the confirm dialog and the Leftovers page and are overridable per run; "Ask" emits no `Scan`
  request until the user asks; "Empty quarantine" sends one `quarantine.purge` with every id and nothing when
  the vault is empty. Script steps for each row. No value of this page reaches the broker except through the
  typed request fields that exist (`quiet`, `restore_point`, `forced`, `other_profiles`).

**16. M4-LEFTOVERS-UI** — the Leftovers page for F4, F5 and F6.
- Files: **`crates/purge-ui-model/src/leftovers/**`**, **`bins/purge-ui/src/screens/leftovers.rs`**, new
  `crates/purge-ui-model/src/keep.rs`, `bins/purge-ui/src/screens/settings.rs` (`CardPacks`, `CardKeep`).
- Does: the Tidy-up group, the Other users section, the notes for `NewScanner` and `KbPack` rows, report-only
  hints with their "Open Settings" links, and "Always keep". **Keep rules are applied in the UI model only**:
  saved in `%LOCALAPPDATA%\Purge\keep.json`, a matching row is unticked and not tickable, and while any rule
  matches the page sends `plan.create` in its `selected` form. The broker never reads the file.
- Tests: a kept row is never in `selected`, also when the broker preselected it; a group box never ticks an
  Other-users, report-only, Tidy-up or kept row; a damaged `keep.json` keeps nothing and is not written over;
  script steps on sample rows of each new kind.

**17. M4-TRAPS** — the installer-built traps of §10.2 as fixtures, so they are not lost while the VM waits.
- Files: `bins/purge-engine/tests/engine/m4_traps.rs` and fixtures.
- One test each, through `pipeline::{harvest, scan}` on a `Fixture`: an app named "Update" and one installed into
  a folder named `Update`; an install into Documents (no root); an install under a sync root; a stale duplicate
  Uninstall entry for the same folder; modify-instead-of-uninstall and a cancelled uninstall that returns 0 (both
  end forced); a dangling reference to a drive that is not mounted (never dangling); a data folder `D:\Library`
  (user data, never whole); a second profile; Defender's native-messaging host and `ShimInclusionList` never
  offered whole. Each asserts no Safe row outside the app and no user data ticked.

**18. M4-EXT-NOFP** — "Look by name" for a removed program with no record. *Fable review.*
- Files: `purge-rpc` (a fourth `leftovers.scan` form `{removed: {program_id, display_name, publisher,
  install_location?, …}}`; this package is the wave's one RPC writer), `bins/purge-broker/src/scan.rs`,
  `bins/purge-engine/src/pipeline.rs`, `purge-ui-model/src/pipeline/removed.rs`.
- The row comes from the medium engine's stored list, a file the user can write. So every root and fact built
  from it has `SourceTrust::UserWritable`, the scan is `Forced`, and Rule T applies.
- Tests: no Safe and no preselected row for any input; a made-up `install_location` pointing at another
  program, a system folder or a user-content folder is refused as in package 4; overlong or odd strings are
  refused by the DTO, not truncated.
- **First to cut** if the milestone runs long: without it such a row keeps saying that Purge has no record.

### 4.3 Conventions for every package

- **Worktree:** `git worktree add -b m4/<name> E:\purge-ui-wt\<name> ui/rust`. Work only there. Never push, never
  touch `ui/rust`, `main`, `baseline` or the main checkout; the coordinator merges.
- **Builds and tests run on the laptop** through `tools/laptop/lt.sh` (read its header): it sends the worktree's
  files and runs cargo there, all worktrees sharing one target directory.
  `tools/laptop/lt.sh E:/purge-ui-wt/<name> test --release -p <crate>`. If the laptop does not answer, stop and
  report; do not build on the PC. `cargo fmt` may run on the PC.
- **The app runs on the PC:** `tools/laptop/lt.sh E:/purge-ui-wt/<name> --fetch Purge.exe purge-engine.exe`
  puts the exes in `E:\purge-target\lt\<name>\`; then
  `powershell -NoProfile -File tools\desk\run-hidden.ps1 -Exe E:\purge-target\lt\<name>\Purge.exe -Args '--sample --script'`.
  Every UI run goes through `run-hidden.ps1`; no window is ever shown or brought to the front.
- **Never on the PC:** the elevated broker, a real uninstall, `plan.execute`, `undo.run`, a UAC confirmation, the
  `rig-exec` CLI against live data. Engine code may be run read-only (inventory, harvest, scan to a file).
- **No VM, no VBoxManage, no outside models, no new third-party crates** without the coordinator's OK. Nothing
  under `vm/` changes except `vm/guest/tests/ui-a11y-probe.ps1` (ids only).
- **Gates before handing back** (all through `lt.sh` except fmt): `cargo fmt --all -- --check`;
  `clippy --release -p <your crates> --all-targets -- -D warnings`; `test --release -p <your crates>`; for engine
  packages also `run --release -p xtask -- check-deps`, `scanner-coverage` and `no-new-walks`; for UI packages
  the scripted walk with your new steps, and `ui-a11y-probe.ps1` on the hidden desktop when you added ids.
- **Style:** the repository's (doc comments that say why, no `unwrap` outside tests, `thiserror` errors).
  Small commits; each message ends with the attribution lines you are given.
- **Hand-back report:** what was built, the tests added per invariant of section 5, any golden that changed and
  why, anything you made report-only or left out, and rows for `docs/DECISIONS.md` for every choice you made.

### 4.4 Releases

| Release | After | Brings |
|---|---|---|
| 0.2.0-beta.1 | packages 1, 4, 5 | Force remove (F1, F2) |
| 0.2.0-beta.2 | 2, 6, 7 | Recording and external scans (F3) |
| 0.2.0-beta.3 | 3, 8 to 12 | New scanners and knowledge packs (F4, F6 rows) |
| 0.2.0-beta.4 | 13 to 18 and the review's fixes | Other users, settings, "Always keep", tidy-up |

Each release note says in its first lines that forced removal, external scans and the new scanners have not been
through the VM gate yet.

## 5. Safety invariants

### 5.1 The invariants and where they are enforced

| # | Invariant | Enforced in | Tests M4 must add |
|---|---|---|---|
| I1 | **Guard.** Every target is canonical, its final path equals its lexical path, it is no link, and it passes the gates at plan time and again before each item | `purge-guard/src/{canon,live}.rs`; `purge-exec/src/gate.rs` | None may be weakened: **no M4 package edits `purge-exec`, `purge-guard/src/{canon,deny,live}.rs` or `kb/deny.json`** except to add value containers (package 8). Package 4: path-scan inputs in every hostile form are refused before the scan |
| I2 | **Deny list.** No candidate, root or pack rule resolves into a deny rule; structural containers are never deleted as keys | `purge-guard/src/deny*`, `containers.rs`; `validate_root` in `purge-harvest/src/roots.rs` | Every scanner: its value containers are in the guard's table and a test offers none of them as a key. Package 3: lint over the deny data. Package 4: refused roots |
| I3 | **Quarantine first.** Nothing is deleted without a verified backup; files move to quarantine; every action has an inverse | `purge-exec` (`execute.rs`, `regbackup.rs`, `act_*.rs`) | No new operation in M4 (3.3), so nothing to add; the review checks that no scanner emits a (target, action) pair outside `Action::pairs_with` and the executor's op table |
| I4 | **Forced mode preselects nothing.** In a forced scan, or when verify-gone did not pass, nothing is Safe and nothing is preselected, whatever the evidence. A path scan, a no-command session and a by-name scan are always forced, and the client can never raise a mode | `purge-policy/src/band.rs` rule 6; `purge-broker/src/scan.rs` (mode choice); `purge-ui-model/src/leftovers/mod.rs` (no invented ticks) | Package 2: the property test. Packages 4 and 18: every entry point. Package 5: the UI shows zero ticks. Every scanner: its candidates in a forced world |
| I5 | **A scanner without rig coverage cannot emit Safe** (§5.6). Every M4 scanner is capped at Likely until the corpus gate | `purge-policy` `UNVALIDATED_SCANNERS`; `xtask scanner-coverage` `M4_PENDING_ROOTS` | Package 2: the cap. Every scanner: a Tier A fixture candidate is Likely and unticked in post mode |
| I6 | **Packs only suggest.** No pack rule is Tier A, Safe or preselected until packs are VM-validated; raising rules load only from the compiled-in set; protective rules can only lower | `purge-model` (`KnowledgeRule` tier data), `purge-policy`, `purge-kb` (load paths) | Packages 2, 3 and 12 |
| I7 | **Report-only classes stay report-only:** UserChoice, live MSI registrations, `%WINDIR%` files (but single Prefetch traces), the ClickOnce store, network profiles, Defender exclusions, dangling links, `Windows\Installer` icon folders, other users' profiles, anything that cannot be backed up | The scanners (`Action::ReportOnly`), `Blocker::OtherProfile`, `plan::decide` (never in a plan), `purge-exec/src/plan_in.rs` | Packages 9, 13, 14: `plan.create` with such an id is refused; the UI gives them no tick (16) |
| I8 | **User data is never preselected**, and unknown AppData folders are user data | `purge-policy` (category and soft blocker), `fs_appdata.rs` | Packages 9 (dotfiles), 12 (`user_data` rules), 17 |
| I9 | **Rule T and the external rule.** Evidence from a user-writable source never attributes a machine-scope target at Tier A; an external scan is Safe only on admin-only evidence | `purge-policy/src/band.rs`, `score.rs` | Packages 6 and 18; every HKU-reading scanner has one case with an HKLM target |
| I10 | **The broker trusts nothing from medium.** Its inventory, harvest, verify-gone and mode are its own; settings reach it only as typed fields; it reads no user-writable file | `purge-broker` (`start.rs`, `uninstall.rs`, `scan.rs`) | Package 6: program ids only. Package 16: keep rules stay in the UI. Package 18: the one place medium data enters, marked `UserWritable` |
| I11 | **Other apps are protected,** in both directions, including other users' installs | `purge-index/src/ownership.rs`; blockers `InsideOtherApp`, `ContainsOtherApp`, `ReferencedByOtherApp`, `OwnedByInstalledMsi` | Package 14 closes the unloaded-profile gap. Every scanner: one case where another installed program owns or references the item |
| I12 | **The store is Purge's.** `ProgramData\Purge` is opened through checked handles; a failing directory is set aside | `purge-exec/src/storage*`, `purge-broker/src/store_caches.rs` | Package 6: the index and the fingerprints go through `DocDir` only |

### 5.2 The common test list of a scanner

Each new scanner, or new location of an old one, has at least: (1) the positive case with its evidence kinds
asserted; (2) another installed program owns or references the item: Blocked or absent; (3) the container is
never a candidate; (4) forced mode: nothing Safe, nothing preselected; (5) external mode with user-writable
evidence only: not Safe; (6) a deny-listed neighbour is not offered; (7) post mode with Tier A: Likely and
unticked (I5); (8) for a scanner reading a user hive: Rule T on a machine target; (9) an entry with hostile text
(a path with `..`, a device name, an overlong name) gives no candidate and no panic.

## 6. Deferred until after 1.0

Nothing here is dropped. Each line names what lifts it.

**Gates and VM work**

- The M4 corpus gate of §11.1: `recall_visible` ≥ 90 % macro (no app < 75 %), `recall_safe` ≥ 75 %, `recall_ext` ≥
  70 %, `recall_force` ≥ 60 %, danger 0, `userdata_preselected` 0, `precision_safe` 100 %; the recall bands of §1.4;
  per-kind and per-scanner recall (no kind < 60 %).
- Runs R-ext and R-force per corpus app (§10.2), execute and undo round trips for forced and external plans,
  crash injection on them.
- The installer-built traps run with real installers in the VM (package 17 holds their fixture forms).
- **Lifting I5:** capture every `M4_PENDING_ROOTS` location in the rig (`vm/rigtool`, RIG.md §2), new null runs
  and ambient set, corpus runs, then scanners leave `UNVALIDATED_SCANNERS` one by one.
- **Lifting I6:** the pack CI of §5.9 (conflict check against baselines and other apps' Tier A footprints, VM
  validation), then `KnowledgeRule{shipped, anchored}` at Tier A.
- `xtask replay-all` / `replay-diff` over the frozen runs with the M4 catalog, and the Mozilla `uninstall.log`
  reader (§6.1; its format is to be verified on real logs).
- Open M3 items from `docs/HANDOFF-ui-rust.md`: the broker start-check fix and its e2e rerun, the m3-broker
  FAIL cases, the consent, uac, recover and clean modes, the B10 reruns, the M3 gate document, the toolkit
  consent dialog as default, the G12 timings.
- The one VM run of the UI, when M4, M5 and M6 are implemented: real uninstall, force remove of a listed
  program and of a folder, record then remove outside then external scan, move, put back.

**Features**

- New executor operations: removing a Defender exclusion (`MSFT_MpPreference`), deleting a dangling link,
  fonts. Each needs the M2 kind of round-trip gate in the VM; report-only until then.
- The user store of §6.2 (a medium-written cache). Section 7, question 2.
- Standard-user accounts (over-the-shoulder elevation) and "Always start as administrator": both are new
  elevated paths with no gate (M3_DESIGN 7 answer 3, and section 15).
- The Store tab, "Modify", closing apps, restarting Explorer, boot-time operations.
- History exports (journal JSON, `.reg`): an elevated process writing to a place the user names needs a design.
- Per-pack switches, local and agent packs and their lifecycle (M6), `ContentMentionsAppPath`.
- Compact rows, the Diagnostics card (log folder, export), localisation.
- v2 rows of §5.6: FS-FONTS, FS-JUMPLISTS, REG-IFEO, SYS-DRIVER, SYS-CERT, X-STORES, X-PFORPHANS.

## 7. Open questions for the user

1. **New scanners and packs come unticked until the VM gate (I5, I6).** This is ENGINE_PLAN's own rule ("a
   scanner without rig coverage cannot emit Safe"), and with the corpus gate after 1.0 it means every M4
   leftover kind is shown but must be ticked by hand in 1.0. *Recommendation: keep the rule.* The other way
   would be to preselect on fixture tests alone, which is the one thing that could put a wrong item in a
   default plan.
2. **Recording needs administrator permission; no medium-level record.** §6.2 also has a user store written
   without a prompt. M3 decided that nothing made at medium integrity is evidence. *Recommendation: admin store
   only*: "Record now" (one Windows prompt) plus automatic recording whenever the broker is open anyway. The
   cost: a program installed and removed outside Purge between two broker runs has no record ("Look by name").
3. **No new delete operations in M4:** Defender exclusions and dangling PATH links are listed with a hint, not
   removed. *Recommendation: yes*, because a new executor operation without its VM round-trip gate is the kind
   of risk the new plan otherwise avoids.
4. **Left for after 1.0 although M3 pointed them at M4:** standard-user accounts, "Always start as
   administrator", the Store tab, "Modify", History exports. *Recommendation: defer all five*; say if one of
   them matters for 1.0 (the Store tab is the largest: listing and removing Store apps).

## 8. ENGINE_PLAN lines that disagree with this plan or with the code

ENGINE_PLAN.md is not edited here. Besides the list in M3_DESIGN §17:

| Where | ENGINE_PLAN says | Now |
|---|---|---|
| §11.1, DECISIONS 2026-11-22 | v1 after M4; M5 = 1.1, M6 = 1.2 | 1.0 = M4 + M5 + M6 (user, 2026-11-28); the M4 exit criteria move behind 1.0 |
| §3.2, §3.3, §9 | `ui/` is C# WinUI with NJsonSchema DTOs; S5 is `Expander` cards | The UI is `bins/purge-ui` on `mdshared-ui`, with `purge-client` and `purge-ui-model`; no DTO codegen on the product path |
| §3.3 methods | `leftovers.scan {session_id \| program_id \| path \| exe}`; `location.inspect`, `references.find`, `guard.explain`, `history.list`, `kb.lint` over RPC | `leftovers.scan` has session and stored forms on the pipe only; M4 adds `path` (no `exe` form: a folder is the unit); the other methods do not exist and M4 does not need them; `kb lint` is a CLI verb, `kb.list` is new |
| §5.1, §5.3 `RememberedManifest`, §6.2 | A pre-harvest cache that attaches `RememberedManifest` evidence, with an admin and a user store | The stored fingerprint is the harvest itself; no such evidence kind; admin store only (question 2) |
| §5.3 `KnowledgeRule{shipped, anchored}` Tier A; §5.9 "shipped packs are active by default" | Packs can reach Safe | Tier B until VM-validated (I6) |
| §4.1, §5.3, §5.5 | Unloaded profiles are read through offreg for ownership | Not implemented; package 14 |
| §5.6 SYS-DEFENDER "Safe · `MSFT_MpPreference.Remove`"; FS-DANGLINGLINKS "Safe · delete link only" | Removable | Report-only in M4 (question 3); `Target::DefenderExclusion` does not exist in the model |
| §5.6 phase column | "M4" rows may emit Safe | Capped by I5 |
| §9 S5 | "Pre-select user data", "Pre-select app caches", "Close running apps without asking", "Always start as administrator" | Not built (section 2, F7) |
| §9 S7 "Remove entry" | A dialog of its own | Part of the forced scan (F1) |
| §3.4 | `scan --fp fp.json --mode external` as the external path | The product path is the broker's stored fingerprint; the CLI form stays for the rig |
| §10.1 `xtask ci` | DTO schema drift, C# tests | The `ui` step is behind `--require-ui`; the WinUI tree is still in the repository but no longer ships |
