# Purge — feature parity plan

> **Superseded in part by ENGINE_PLAN.md (2026-11-11); edits per §11.5 applied.** Where the two disagree,
> `docs/ENGINE_PLAN.md` wins.

Target: match **Uninstall Tool 3.8.2** results (feature list taken from its `languages/English.xml`),
implemented by porting **Bulk Crap Uninstaller** logic (Apache-2.0, https://github.com/Klocman/Bulk-Crap-Uninstaller)
to Rust. Rule: where BCU is better than UT, BCU's behavior wins. No UT code, binaries or strings are reused.

Attribution: ported BCU logic keeps a `// Ported from BCU: <path>` comment, and `NOTICE` carries BCU's notice.

Legend: **v1** = first release, **v2** = later, **—** = dropped (not useful for a private build).

## Uninstaller (program list)

The inventory is written fresh from BCU and Microsoft docs (ENGINE_PLAN.md §4); the clone's list builder is
not reused.

| UT feature | Purge | BCU source to port | Notes |
|---|---|---|---|
| Program list: name, size, installed-on, version, publisher | v1 | `Factory/RegistryFactory.cs`, `ApplicationUninstallerEntry.cs` | HKLM + HKLM\WOW6432Node + HKCU (+ per-user hives) |
| 32-bit marking | v1 | `InfoAdders/Is64BitGetter.cs` | |
| Size calculation | v1 | `InfoAdders/FastSizeGenerator.cs` | |
| Icons | v1 | `InfoAdders/BasicIconGetter.cs`, `FileIconGetter.cs` | |
| Categories (program list tabs) | v1 | `SystemComponent`, `ParentKeyName`, `WindowsUpdateFactory.cs` | Purge's own tab names: Apps / Components / Unnamed / Store / Recent (ENGINE_PLAN.md §9.4 S1) |
| Tree-like updates (sub-items under parent) | v1 | `ParentKeyName` grouping | UT does this better than BCU's flat list → follow UT |
| Recently installed filter + highlight | v1 | `InfoAdders/InstallDateAdder.cs` | Popup on new programs → v2 |
| Search / sort | v1 | — | |
| Uninstall (run built-in uninstaller) | v1 | `UninstallerType`, `ApplicationUninstallerEntry` | |
| Modify | v1 | `ModifyPath` | |
| Batch uninstall | v1 | `BulkUninstallTask` | BCU is better: queue, quiet mode, concurrency → follow BCU |
| Silent/quiet uninstall | v1 | `NsisQuietUninstallStringGenerator`, `InnoSetupQuiet…`, `MsiUninstallStringGenerator`, `PredefinedAppQuiet…` | Not in UT; BCU extra |
| Uninstall failed → offer cleanup | v1 | — | |
| Running processes → offer terminate | v1 | `Junk/Containers/RunProcessJunk.cs` | |
| Force removal (+ batch) | v1 | `Junk/*` with entry as input | Confirmation checkbox like UT |
| Remove entry (+ batch) | v1 | registry key delete | |
| Jump to: registry, install folder, website, browse location/source, search online | v1 | — | |
| Microsoft Store apps | v1 | `Factory/StoreAppFactory.cs` | PackageManager, lazy tab; sparse packages linked only by external location or harvest |
| Steam / Scoop / Chocolatey / Windows features | v2 | `SteamFactory`, `ScoopFactory`, `ChocolateyFactory`, `WindowsFeatureFactory` | BCU extras |
| Export list to HTML | v2 | — | |
| Explorer "Uninstall with Purge" on shortcuts | v2 | — | |

## Uninstall Wizard (leftover scan)

| UT feature | Purge | BCU source to port | Notes |
|---|---|---|---|
| Scan files/folders after uninstall | v1 | `Finders/Drive/CommonDriveJunkScanner`, `InstallLocationScanner`, `UninstallerLocationScanner`, `SpecificUninstallerKindScanner`, `PrefetchScanner`, `WerScanner` | |
| Scan registry | v1 | `Finders/Registry/*` (SoftwareRegKey, Com, AppCompatFlag, EventLog, FirewallRule, InstallerFolders, RegisteredApplications, Tracing, DebugTracing, HeapLeakDetection, AudioPolicyConfig) | BCU covers more locations than UT is known to |
| Shortcuts / startup leftovers | v1 | `Finders/Misc/ShortcutJunk`, `StartupJunk` | |
| Review tree (File System / Registry, counts, size) | v1 | — | UT's grouped tree UI |
| Pre-uninstall harvest | v1 | — | Before the vendor uninstaller runs: validated roots, exes, reference snapshot, tokens, co-removed products (ENGINE_PLAN.md §5.2, §6) |
| Verify-gone after uninstall | v1 | — | ARP entry gone, MSI product unknown in all contexts, exes gone; otherwise no leftover scan |
| Inno / MSI / Burn readers | v1 | — | Inno uninstall log, MSI tables (Registry/ProgId/Extension/Class/TypeLib/Environment rows), Burn children and dependents |
| Scanner catalog | v1 | `Finders/*` (re-specified) | ENGINE_PLAN.md §5.6, rolled out M1a / M1b / M4 |
| Evidence per item | v1 | — (replaces `Junk/Confidence/*`) | Evidence model in place of BCU confidence: typed evidence tiers and blockers, value- vs key-level scope, bands Safe / Likely / Weak / Blocked (ENGINE_PLAN.md §5.3, §5.8). Each item keeps its evidence for explanation and AI review |
| Ask / automatic / disabled after uninstall | v1 | — | |
| Delete; locked files → delete on reboot | v1 | `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` | |
| Backup before delete + restore | v1 | BCU exports .reg backups | Purge: same-volume quarantine + lossless JSON registry backup (.reg on demand) + hashed journal + typed undo; restore point optional (ENGINE_PLAN.md §7). Files go to quarantine on their own volume; registry keys and values are backed up as `purge.regbackup/1` JSON (raw type and bytes, names, class, security, link flag), read back before the delete, and the journal holds the SHA-256 of every backup file, checked on undo. As of M2, undo covers files and registry; services, scheduled tasks and firewall rules get their full definitions and typed undo with M1b, and AppX removal stays irreversible (never preselected) (ENGINE_PLAN.md Appendix B, M2 deviations) |
| Save log / export results | v1 | — | JSON instead of XML |

## Install Tracker

| UT feature | Purge | Notes |
|---|---|---|
| Install and trace, revert, traced force removal, append, dependent items, custom entries | v2 | UT uses a kernel driver service. BCU has nothing here. Purge: ETW file/registry tracing + snapshot diff, no custom driver |

## Startup manager

| UT feature | Purge | BCU source |
|---|---|---|
| Run / RunOnce (HKLM/HKCU), Startup folders, logon tasks, Store startup tasks; enable/disable/delete/add | v2 | `Startup/*` (StartupManager) |

## Dropped

Trial/registration, update checker, Control Panel applet, Total Commander integration, UAC-bypass scheduled task
(Purge uses an asInvoker UI + on-demand elevated broker; final consent in the broker; optional "always start as administrator"), interface languages (English only), System Tools menu shortcuts (cheap to add later).

## AI cleanup (future)

Deterministic scanners produce every candidate with its evidence. AI may propose probes and signatures; only
engine evidence creates candidates; agent items are never preselected; AI evidence never raises a band; AI
never executes (ENGINE_PLAN.md §8). A hard deny-list (Windows, System32, shared components, other installed apps'
folders/keys) always applies, and everything deleted is backed up first.
