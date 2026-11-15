# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 5 | 365 | 20.6% | 18.4% | 7.1% | 20.6% | 18.4% | 7.1% | 65.0% | 3 | 8 | 3 | 0 | 0 | 0 | 12.7% | 24.1% | 44.0% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 14 | 28 | 32.1% | 21.4% | 17.9% | 32.1% | 21.4% | 17.9% | 100.0% | 1 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 9 | 198 | 1.0% | 0.5% | 0.0% | 1.0% | 0.5% | 0.0% | - | 0 | 5 | 0 | 0 | 0 | 4 | 5 | 0 | 0 | 0 | 0 |
| git | purge | 5 | 70 | 5.7% | 5.7% | 5.7% | 5.7% | 5.7% | 5.7% | 80.0% | 0 | 1 | 1 | 0 | 0 | 4 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 3 | 44 | 52.3% | 52.3% | 0.0% | 52.3% | 52.3% | 0.0% | 0.0% | 0 | 1 | 1 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |
| vlc | purge | 7 | 25 | 12.0% | 12.0% | 12.0% | 12.0% | 12.0% | 12.0% | 80.0% | 2 | 1 | 1 | 0 | 0 | 6 | 1 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox | purge | 2/10 20.0% | 3/11 27.3% | 4/5 80.0% | 0/2 0.0% |
| vscode-user | purge | 0/43 0.0% | 2/153 1.3% | 0/2 0.0% | 0/0 - |
| git | purge | 0/55 0.0% | 2/9 22.2% | 2/6 33.3% | 0/0 - |
| npp | purge | 5/17 29.4% | 16/23 69.6% | 2/3 66.7% | 0/1 0.0% |
| vlc | purge | 1/7 14.3% | 0/12 0.0% | 2/5 40.0% | 0/1 0.0% |

## Truth labels and ambient removal

- **firefox**: ambient=576, kept_owner=0, leftover=27, rig=0, user_data=1; ambient: f0d-null1 removed 542, f0d-null2 removed 550
- **vscode-user**: ambient=767, kept_owner=0, leftover=171, rig=0, user_data=27; ambient: f0d-null1 removed 704, f0d-null2 removed 701
- **git**: ambient=578, kept_owner=0, leftover=70, rig=0, user_data=0; ambient: f0d-null1 removed 545, f0d-null2 removed 550
- **npp**: ambient=569, kept_owner=0, leftover=44, rig=0, user_data=0; ambient: f0d-null1 removed 472, f0d-null2 removed 481
- **vlc**: ambient=516, kept_owner=0, leftover=25, rig=0, user_data=0; ambient: f0d-null1 removed 493, f0d-null2 removed 501

## Danger items

- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId; deny: Packaged COM catalog; maintained by the deployment service, removed with the package.
- vscode-user / purge: `K:HKLM\SOFTWARE\Classes\Applications\Code.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\Code.exe
- git / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- npp / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- vlc / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| vscode-user | purge | 0 | 0 | 5 | 0 | 0 | 0 | 0 |
| git | purge | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| npp | purge | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| vlc | purge | 1 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

- git / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- npp / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15
- vlc / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15

### (1) blocking user data

None.

### (2) unticked danger

- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|_IndexKeys; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId; deny: Packaged COM catalog; maintained by the deployment service, removed with the package.
- vscode-user / purge: `K:HKLM\SOFTWARE\Classes\Applications\Code.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\Code.exe

### (2) unticked user data

- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox / purge (19 missed)

- `P:C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice_tmp.exe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\14b7b9705e64d3daf55e4e380a06974af0870bcb` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\bdba956d11d9c49c34acdcd9e2b473043f6702c0` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\5EB6.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2236` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3852` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7680` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7832` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8748` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9192` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MozillaMaintenanceService|EstimatedSize` [leftover]

### vscode-user / purge (196 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\625a0badee8724db8c992f7cbbbc53625cb7a1f7` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\WER\ReportArchive\Critical_powershell.exe_40179dfbce13215115b8d4c684af6f0accde3c0_00000000_91355bd8-cc73-4298-b0ab-4366dcdf0d15` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\WER\Temp\467dbb3e-5a98-48ff-ad01-5a800091e634` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\6703.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794586471.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794586499.log` [leftover]
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
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2896` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3508` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7660` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8276` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8436` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8560` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8568` [leftover]

### git / purge (66 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\00a0571f2e75bdbdd1a2476a8f894a751bbb6d3d` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\023a60659a674e54ec28181343a64409ed42b400` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\06a78a5645e54b087e1e98212728806a8db91c5a` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\19532a680aa3420e61664931b9ffedfc5a1ba46a` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\1a14dd3bfe79d2677247914a804e7754c6f31697` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\1a7ea54f6ed02a958f65aa2226248734bd56d99a` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\1cfcee50405ebfdb8f11806507aa1b6c09343a88` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\215f421eb2965abeaba336bc872b6baed3ad2929` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\2887af2f91c272cc4829b2ff0238f13b2ae3ebfd` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\344f05eb83af92c40c748463948725251c738c4e` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\3dcc2492699ea5c60c614e1434015b0267bd7746` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\44bee4b0e7a927be8238f640c33f0c6e79595fa3` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\46f0a6a555aa8249a19d8b09f26e6a40c13a5c5c` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\47d65966c7941d8252c2298ad88f740ddb0ec587` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\4be137227be808041a402f9df149ffff608a5748` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\52d3e5e7c1e5c3fee22feea83a42ef2286081f5d` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\5334250fad7dc8c2d38d17ff3be3cd409594f9c1` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\54eb70ce51988452f4fa701e01b7ed8495bc67cb` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\5827c774512d5e22881d612a707453e0a096e7d8` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\67a741815ef358e68feb3b8e940458fb521b99b5` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\67b3cd670047089266e01017085a1b1aae1ad3c6` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\69c2682db33c6e44983cc08652bfe5bba028cfd4` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\6bfde811aa6cd64557cac2f6ed17f2f8ad0e9e6d` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\6d28173a6dd999c35109a6d986801a4ec0b63fdc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\6f49b764ba4c14539409f00dbb05c076f107d437` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\76ff5e6d53d79431e8b60382495a9791a71809a2` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\7cfd606bab2a9684a0da37a04f593280049fbeb9` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\7e3c47be81abe977d8758241de99fda97af688b5` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\809974c2bf5e9bc2e43c0b1046c18850b345f0e3` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\8101c898b3ce5ce0d474afe8c686e224470a88a4` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\8b8a62ae1c6b40344f83d09edfdd61cc24cddb73` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\913abd8e016add0726f43213787bbe7e6f672c11` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\9bfdb8b6afd9ad819391d25093fa5eafd20f0122` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\9d3fbeca6b2a10d0e11fdd9c82d9effb47b3e2b5` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\a37f8481397ecaf29f2f05c3c436ef3c72c7c9b1` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\add10b66dd86067c30062dcf89638cd28f931adf` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\b1df22f585c4032b1e8104a95a50d797cb7695a0` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\b437bbdccfa9dd6842ec7d4d441e2b728c239365` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\b65222eb0683ab0a8f914814c63380ff1103ef67` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\be22493ae468e0ba43e8a8bb21b6a07f6cd06963` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c245ed79a11abff174bb64c59d94ae7d8342ee32` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c28c39b9e0f1ca7e2ad1ad64b398a041c1bd25e4` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c796a2b023302d94a64906393bebeedfa352f844` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\d881a0a5c39ac9e1776249940a29f3c54c159ada` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\eead82ac70d9422807269eb2da4c7dda2a63df36` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\eeb70461a04f10152892e79a10b8e79d307052a1` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\76A3.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-AWLY028RWJ-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]

### npp / purge (21 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\052efd195dfac7752f1a205d5ca7be92a0858d7c` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\0e15c296a025b778e59bea398d3274e854f392b8` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\6f52a772029428f3f17f3adb0ae67c2fbfce6a2f` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\a57a73c72be35a4c435220a66aaaa780bdb6d565` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\b0a9cb6a58a8923840820347fdba1d945aa11d2d` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\e3bcc64d8ffbd329541bcc0c9e87d834385301bc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\a4acf73c-e96c-4225-ab40-3ce3e4f2340d_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\4E5A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem8DD9.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1732` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4260` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7324` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7360` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7892` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8068` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\844` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### vlc / purge (22 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\6b85e4a067ed7e59aa04da4185d5a419c4927a9c` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\9e5dd417ef7e380f111291403cee73fcf6619cca` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\b8ab2eba7deb1b4948d5ef06fbe9744e28991443` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DF8E.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\VLC.EXE-46412408.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\DVD\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\VideoLAN.VLCPlugin.2` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\VLCPlayBlurayOnArrival` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1400` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1756` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2164` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2348` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7372` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7704` [leftover]
- `K:HKLM\SOFTWARE\MozillaPlugins` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings\11450564399206804176` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Ext\Stats` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\PlayBluRayOnArrival|VLCPlayBlurayOnArrival` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\VideoLAN\VLC\vlc.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\IvqrbYNA\IYP\iyp.rkr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings|UIOrderList` [leftover]

