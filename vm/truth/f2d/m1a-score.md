# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 5 | 245 | 31.6% | 28.5% | 8.6% | 31.6% | 28.5% | 8.6% | 100.0% | 3 | 3 | 4 | 7 | 0 | 0 | 0 | 0 | 0 | 19.8% | 34.6% | 50.7% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 14 | 20 | 45.0% | 30.0% | 25.0% | 45.0% | 30.0% | 25.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 8 | 159 | 1.3% | 0.6% | 0.0% | 1.3% | 0.6% | 0.0% | - | 0 | 0 | 4 | 4 | 0 | 0 | 0 | 0 | 4 | 4 | 0 | 0 | 0 | 0 |
| git | purge | 5 | 17 | 23.5% | 23.5% | 11.8% | 23.5% | 23.5% | 11.8% | 100.0% | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 4 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 3 | 33 | 69.7% | 69.7% | 0.0% | 69.7% | 69.7% | 0.0% | - | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |
| vlc | purge | 7 | 16 | 18.8% | 18.8% | 6.2% | 18.8% | 18.8% | 6.2% | 100.0% | 2 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 6 | 1 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox | purge | 2/7 28.6% | 3/7 42.9% | 4/5 80.0% | 0/1 0.0% |
| vscode-user | purge | 0/13 0.0% | 2/145 1.4% | 0/1 0.0% | 0/0 - |
| git | purge | 0/7 0.0% | 2/5 40.0% | 2/5 40.0% | 0/0 - |
| npp | purge | 5/11 45.5% | 16/18 88.9% | 2/3 66.7% | 0/1 0.0% |
| vlc | purge | 1/4 25.0% | 0/8 0.0% | 2/3 66.7% | 0/1 0.0% |

## Truth labels and ambient removal

- **firefox**: ambient=778, kept_owner=2, leftover=19, rig=1, user_data=1; ambient: f2d-null1 removed 637, f2d-null2 removed 619
- **vscode-user**: ambient=846, kept_owner=27, leftover=159, rig=0, user_data=0; ambient: f2d-null1 removed 781, f2d-null2 removed 779
- **git**: ambient=1032, kept_owner=0, leftover=17, rig=1, user_data=0; ambient: f2d-null1 removed 848, f2d-null2 removed 836
- **npp**: ambient=659, kept_owner=0, leftover=33, rig=0, user_data=0; ambient: f2d-null1 removed 584, f2d-null2 removed 577
- **vlc**: ambient=799, kept_owner=0, leftover=16, rig=0, user_data=0; ambient: f2d-null1 removed 783, f2d-null2 removed 781

## Danger items

- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|ApplicationUserModelId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\56|PackageRelativeApplicationId; deny: Report-only: StateRepository is owned by the AppX deployment service; packages are removed through the package API.
- vscode-user / purge: `V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Classes\PackagedCom\Package\Microsoft.VisualStudioCode_1.0.146.0_neutral__8wekyb3d8bbwe\Server\0|ApplicationId; deny: Packaged COM catalog; maintained by the deployment service, removed with the package.
- vscode-user / purge: `K:HKLM\SOFTWARE\Classes\Applications\Code.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\Code.exe
- git / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15; replaced: before 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer PowerShell for VS 2022.lnk | C:\Windows\SysWOW64\WindowsPowe', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Git\Git Bash.lnk | C:\Program Files\Git\git-bash.exe | --cd-to-home'
- npp / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15; replaced: before 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer PowerShell for VS 2022.lnk | C:\Windows\SysWOW64\WindowsPowe', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk | C:\Program Files\Notepad++\notepad++.exe'
- vlc / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15; replaced: before 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer PowerShell for VS 2022.lnk | C:\Windows\SysWOW64\WindowsPowe', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\VideoLAN\VLC media player - reset preferences and cache files.lnk | C:\Program Files\VideoLAN\VLC\vlc.exe | --r'

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| git | purge | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| npp | purge | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| vlc | purge | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

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

### (3) replaced_value

- git / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15; replaced: before 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer PowerShell for VS 2022.lnk | C:\Windows\SysWOW64\WindowsPowe', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Git\Git Bash.lnk | C:\Program Files\Git\git-bash.exe | --cd-to-home'
- npp / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15; replaced: before 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer PowerShell for VS 2022.lnk | C:\Windows\SysWOW64\WindowsPowe', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk | C:\Program Files\Notepad++\notepad++.exe'
- vlc / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|15; replaced: before 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Visual Studio 2022\Visual Studio Tools\Developer PowerShell for VS 2022.lnk | C:\Windows\SysWOW64\WindowsPowe', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\VideoLAN\VLC media player - reset preferences and cache files.lnk | C:\Program Files\VideoLAN\VLC\vlc.exe | --r'

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox / purge (11 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\276A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{ACB05281-AD45-4158-9D88-41C3EEA3C2E7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{B918C4DE-6120-44B3-8996-232E498E2B86}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]

### vscode-user / purge (157 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\EE0A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794706746.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794706773.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.ascx` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.asp` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.aspx` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bash` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bash_login` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bash_logout` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bash_profile` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bashrc` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bib` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.bowerrc` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.c` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.c++` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cc` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cfg` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cjs` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.clj` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cljs` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cljx` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.clojure` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cls` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cmake` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.code-workspace` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.coffee` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.config` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.containerfile` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cpp` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cs` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cshtml` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.csproj` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.css` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.csv` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.csx` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.ctp` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.cxx` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.dart` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\.diff` [leftover]

### git / purge (13 missed)

- `P:C:\Users\tester\AppData\Local\Temp\D581.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-LDPFHAHM42-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{772AE187-F242-4F40-989C-05CD59E9A66C}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{90D7BA47-CDE2-47A2-A846-D53077D4028E}` [leftover]
- `K:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]

### npp / purge (10 missed)

- `P:C:\ProgramData\Microsoft\Windows\AppRepository\1cf54d34-d4cc-46ec-b1a3-52d6010e1715_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\2AE4.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\temD9EB.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{BAE39839-9908-4795-ABB5-3B14058C46DF}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{C9FB245D-2B6A-4F82-9BCC-7752692EB2FC}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### vlc / purge (13 missed)

- `P:C:\Users\tester\AppData\Local\Temp\FA8D.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\VLC.EXE-46412408.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{26A3D269-24E7-4424-8561-B06D88CE8F5D}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{D58E7D06-A85A-4722-ABD2-74EBA0F5F62F}` [leftover]
- `K:HKLM\SOFTWARE\Classes\DVD\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\VideoLAN.VLCPlugin.2` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\VLCPlayBlurayOnArrival` [leftover] (partial)
- `K:HKLM\SOFTWARE\MozillaPlugins` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings\13154034922717704013` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Ext\Stats` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\PlayBluRayOnArrival|VLCPlayBlurayOnArrival` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings|UIOrderList` [leftover]

