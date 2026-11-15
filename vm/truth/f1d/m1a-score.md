# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 5 | 338 | 21.3% | 19.0% | 5.3% | 21.3% | 19.0% | 5.3% | 100.0% | 3 | 8 | 0 | 0 | 0 | 0 | 13.7% | 22.8% | 44.0% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 14 | 27 | 33.3% | 22.2% | 18.5% | 33.3% | 22.2% | 18.5% | 100.0% | 1 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 9 | 195 | 1.0% | 0.5% | 0.0% | 1.0% | 0.5% | 0.0% | - | 0 | 5 | 0 | 0 | 0 | 4 | 5 | 0 | 0 | 0 | 0 |
| git | purge | 5 | 45 | 8.9% | 8.9% | 4.4% | 8.9% | 8.9% | 4.4% | 100.0% | 0 | 1 | 0 | 0 | 0 | 4 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 3 | 44 | 52.3% | 52.3% | 0.0% | 52.3% | 52.3% | 0.0% | - | 0 | 1 | 0 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |
| vlc | purge | 7 | 27 | 11.1% | 11.1% | 3.7% | 11.1% | 11.1% | 3.7% | 100.0% | 2 | 1 | 0 | 0 | 0 | 6 | 1 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox | purge | 2/8 25.0% | 3/12 25.0% | 4/5 80.0% | 0/2 0.0% |
| vscode-user | purge | 0/40 0.0% | 2/153 1.3% | 0/2 0.0% | 0/0 - |
| git | purge | 0/28 0.0% | 2/11 18.2% | 2/6 33.3% | 0/0 - |
| npp | purge | 5/17 29.4% | 16/23 69.6% | 2/3 66.7% | 0/1 0.0% |
| vlc | purge | 1/7 14.3% | 0/14 0.0% | 2/5 40.0% | 0/1 0.0% |

## Truth labels and ambient removal

- **firefox**: ambient=575, kept_owner=0, leftover=26, rig=0, user_data=1; ambient: f1d-null1 removed 541, f1d-null2 removed 510
- **vscode-user**: ambient=815, kept_owner=0, leftover=168, rig=0, user_data=27; ambient: f1d-null1 removed 756, f1d-null2 removed 713
- **git**: ambient=626, kept_owner=0, leftover=45, rig=1, user_data=0; ambient: f1d-null1 removed 591, f1d-null2 removed 503
- **npp**: ambient=624, kept_owner=0, leftover=44, rig=0, user_data=0; ambient: f1d-null1 removed 539, f1d-null2 removed 510
- **vlc**: ambient=673, kept_owner=0, leftover=27, rig=1, user_data=0; ambient: f1d-null1 removed 637, f1d-null2 removed 518

## Danger items

- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId; deny: Packaged COM catalog; maintained by the deployment service, removed with the package.
- vscode-user / purge: `K:HKLM\SOFTWARE\Classes\Applications\Code.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\Code.exe
- git / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- npp / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- vlc / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| vscode-user | purge | 0 | 0 | 5 | 0 | 0 | 0 | 0 |
| git | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| vlc | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId; deny: Packaged COM catalog; maintained by the deployment service, removed with the package.
- vscode-user / purge: `K:HKLM\SOFTWARE\Classes\Applications\Code.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\Code.exe
- git / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- npp / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- vlc / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15

### (2) unticked user data

- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox / purge (18 missed)

- `P:C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice_tmp.exe` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\823C.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4144` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5184` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5476` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5692` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5928` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6672` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8416` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MozillaMaintenanceService|EstimatedSize` [leftover]

### vscode-user / purge (193 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\76A3.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794594342.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794594368.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code\agent-host` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\agentSessionData` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Backups` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\blob_storage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Cache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedConfigurations` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedProfilesData` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Code Cache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\DawnGraphiteCache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\DawnWebGPUCache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\DIPS` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\GPUCache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\languagepacks.json` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Local State` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Local Storage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\logs` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\machineid` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Network` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Preferences` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Session Storage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Shared Dictionary` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\chatLanguageModels.json` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\globalStorage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\History` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\workspaceStorage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1224` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1708` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1772` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3788` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4476` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5964` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7340` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7728` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.ascx` [leftover]

### git / purge (41 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\0d57c12aa5b8d6a03f5cf0be37e3e6fcc34a842c` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\16047a09e43c3388478f32747ceb2e8623894bee` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\19626afa2faae44d46d7166e2f246878dfe104d6` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\3e4be6607fa6e49d996e32014a7787915822d05b` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\4169436c4145df87df75a83b3aba6c3ba21648fd` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\51afc2c2555599ef0640f6052e4bb3fd87a2686d` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\55c7cb662dfbd47cf1b0e393a79a045d11735c4c` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\81ca8e4976b282bd306970e03603b937c7c6ee16` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\8bac3e6b8504ae20375a73799b80444a0d41ba64` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\9b469492fd0dfff31dcc0a915629aa43b4110f87` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\a94468ac1161fbf3455743d2f2b3e1b18c9bb372` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\aadfc59a4702d33b060068db85e0ff353df50af7` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c65b472e8a4a6c890a1fafb6dc5265e966eb6015` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c70b7f68f2914b919a987951dababcaf377e0550` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c9e295d7de3120d5f0054cc2b39b8d6c2d5449d0` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\cc0577f88825e4a81e0b2643ed7dc54f6a8063c1` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\ded1f7da80d73cc70f3480bdce7f721359a2153a` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\f2188af296712b25c65d7c6b0d96e22feb6c020b` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\f5b1545a2be39f077b48cf5628394fdbb436f5d1` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\79C0.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-842T62DK14-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2908` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3132` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3908` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5724` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7456` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7608` [leftover]
- `K:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]

### npp / purge (21 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\44b56b36da535c08ef617f32a9613c1d3eaa6ecb` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\582da6d57d3cf9008c9b1039a547366342b42bd3` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\729c620681452b78131f27f9d96a5dcd4ee179f8` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\7e3114bcf5da1e0218a30a082f72082ba715b665` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\939b21f51d60f70be92a52f6a2c2150c0ff9d480` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\fedf4ae53933adaf88d8a3cfde712f1846b777d8` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\3f0c7e4f-f1d1-4764-8a27-e46f2d1ac67e_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\8EBF.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem2A0A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2884` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3648` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3800` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3984` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7040` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7256` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7368` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### vlc / purge (24 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\35bb26d2e5399eafa40be8b07588ebb6bb81a10b` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\cd75a4e34da70eacce8212fb8d4139430edad7d7` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\edced5f425e940898c75c57f9fa8eac43ddb64fc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\8818.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\VLC.EXE-46412408.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\DVD\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\VideoLAN.VLCPlugin.2` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\VLCPlayBlurayOnArrival` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1944` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4544` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4928` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4968` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5268` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5288` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5700` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5840` [leftover]
- `K:HKLM\SOFTWARE\MozillaPlugins` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings\10989488020820923683` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Ext\Stats` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\PlayBluRayOnArrival|VLCPlayBlurayOnArrival` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\VideoLAN\VLC\vlc.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\IvqrbYNA\IYP\iyp.rkr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings|UIOrderList` [leftover]

