# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 5 | 270 | 4.6% | 4.6% | 4.6% | 4.6% | 4.6% | 4.6% | 96.3% | 4 | 0 | 0 | 1 | 0 | 0 | 0.0% | 7.6% | 0.0% | 0.0% |
| purge | 7 | 477 | 43.7% | 40.9% | 29.2% | 43.7% | 40.9% | 29.2% | 98.0% | 5 | 0 | 0 | 0 | 0 | 0 | 19.7% | 46.0% | 35.7% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vscode | bcu | 202 | 155 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 202 | 0 | 0 |
| vscode | purge | 139 | 155 | 88.4% | 88.4% | 87.1% | 88.4% | 88.4% | 87.1% | 100.0% | 0 | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 147 | 181 | 80.1% | 79.6% | 78.5% | 80.1% | 79.6% | 78.5% | 100.0% | 0 | 0 | 0 | 0 | 0 | 147 | 0 | 0 | 0 | 0 | 0 |
| git | bcu | 14 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 |
| git | purge | 4 | 30 | 13.3% | 13.3% | 6.7% | 13.3% | 13.3% | 6.7% | 100.0% | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| firefox | bcu | 17 | 39 | 10.3% | 10.3% | 10.3% | 10.3% | 10.3% | 10.3% | 88.9% | 4 | 0 | 0 | 1 | 0 | 8 | 0 | 1 | 8 | 0 | 0 |
| firefox | purge | 20 | 39 | 25.6% | 17.9% | 12.8% | 25.6% | 17.9% | 12.8% | 90.0% | 4 | 0 | 0 | 0 | 0 | 19 | 0 | 1 | 0 | 0 | 0 |
| firefox-tb | purge | 14 | 26 | 34.6% | 23.1% | 19.2% | 34.6% | 23.1% | 19.2% | 100.0% | 1 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| npp | bcu | 10 | 36 | 2.8% | 2.8% | 2.8% | 2.8% | 2.8% | 2.8% | 100.0% | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 9 | 0 | 0 |
| npp | purge | 2 | 36 | 63.9% | 63.9% | 0.0% | 63.9% | 63.9% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| 7zip | bcu | 20 | 10 | 10.0% | 10.0% | 10.0% | 10.0% | 10.0% | 10.0% | 100.0% | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 19 | 0 | 0 |
| 7zip | purge | 0 | 10 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| vscode | bcu | 0/13 0.0% | 0/140 0.0% | 0/2 0.0% | 0/0 - |
| vscode | purge | 1/13 7.7% | 136/140 97.1% | 0/2 0.0% | 0/0 - |
| vscode-user | purge | 1/14 7.1% | 144/158 91.1% | 0/2 0.0% | 0/7 0.0% |
| git | bcu | 0/7 0.0% | 0/10 0.0% | 0/6 0.0% | 0/7 0.0% |
| git | purge | 0/7 0.0% | 2/10 20.0% | 2/6 33.3% | 0/7 0.0% |
| firefox | bcu | 0/5 0.0% | 4/19 21.1% | 0/7 0.0% | 0/8 0.0% |
| firefox | purge | 2/5 40.0% | 4/19 21.1% | 4/7 57.1% | 0/8 0.0% |
| firefox-tb | purge | 2/6 33.3% | 3/13 23.1% | 4/7 57.1% | 0/0 - |
| npp | bcu | 0/10 0.0% | 1/23 4.3% | 0/3 0.0% | 0/0 - |
| npp | purge | 5/10 50.0% | 16/23 69.6% | 2/3 66.7% | 0/0 - |
| 7zip | bcu | 0/2 0.0% | 1/8 12.5% | 0/0 - | 0/0 - |
| 7zip | purge | 0/2 0.0% | 0/8 0.0% | 0/0 - | 0/0 - |

## Truth labels and ambient removal

- **vscode**: ambient=245, kept_owner=0, leftover=153, rig=0, user_data=2; ambient: r1-null1 removed 152, r1-null2 removed 162, r1-null3 removed 161
- **vscode-user**: ambient=411, kept_owner=0, leftover=179, rig=1, user_data=2; ambient: r1-null1 removed 175, r1-null2 removed 185, r1-null3 removed 185
- **git**: ambient=207, kept_owner=0, leftover=30, rig=1, user_data=0; ambient: r1-null1 removed 142, r1-null2 removed 160, r1-null3 removed 128
- **firefox**: ambient=249, kept_owner=0, leftover=38, rig=1, user_data=1; ambient: r1-null1 removed 185, r1-null2 removed 182, r1-null3 removed 169
- **firefox-tb**: ambient=205, kept_owner=2, leftover=25, rig=0, user_data=1; ambient: r1-null1 removed 161, r1-null2 removed 166, r1-null3 removed 157
- **npp**: ambient=256, kept_owner=0, leftover=36, rig=0, user_data=0; ambient: r1-null1 removed 156, r1-null2 removed 167, r1-null3 removed 157
- **7zip**: ambient=178, kept_owner=0, leftover=10, rig=0, user_data=0; ambient: r1-null1 removed 146, r1-null2 removed 159, r1-null3 removed 156

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### vscode / bcu (155 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794590617.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ascx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.asp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.aspx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_login` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_logout` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_profile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bashrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bib` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bowerrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c++` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cc\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cfg` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cjs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clj` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clojure` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cls\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cmake` [leftover]
- `K:HKLM\SOFTWARE\Classes\.code-workspace` [leftover]
- `K:HKLM\SOFTWARE\Classes\.coffee` [leftover]
- `K:HKLM\SOFTWARE\Classes\.config` [leftover]
- `K:HKLM\SOFTWARE\Classes\.containerfile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cpp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cs\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cshtml` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csproj\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.css\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csv\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ctp` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cxx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dart` [leftover]
- `K:HKLM\SOFTWARE\Classes\.diff` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dockerfile` [leftover]

### vscode / purge (18 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794590617.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]

### vscode-user / purge (36 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794590914.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794590940.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1396` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1428` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1656` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7216` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7484` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7492` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7676` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7788` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8176` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]

### git / bcu (30 missed)

- `P:C:\Users\tester\AppData\Local\Temp\is-35I55BLIUL-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\sh_auto_file` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1500` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2900` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4332` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4784` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5996` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6820` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7356` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]

### git / purge (26 missed)

- `P:C:\Users\tester\AppData\Local\Temp\is-35I55BLIUL-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1500` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2900` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4332` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4784` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5996` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6820` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7356` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]

### firefox / bcu (35 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Mozilla` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\remote-settings-startup-bundle-` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Mozilla` [user_data] (partial)
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3388` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4812` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5752` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7080` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7216` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\808` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8472` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` [leftover] (partial)
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` [leftover] (partial)
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{C06245A2-9F3E-4635-AE73-666F142FC703}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Usage|SwarmCount` [leftover]

### firefox / purge (29 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\remote-settings-startup-bundle-` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3388` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4812` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5752` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7080` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7216` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\808` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8472` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Usage|SwarmCount` [leftover]

### firefox-tb / purge (17 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2484` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2624` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3564` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3940` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4260` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5192` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8412` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]

### npp / bcu (35 missed)

- `P:C:\Program Files\WindowsApps\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\4618cfc9-8253-46bc-b94d-6be423bb7531_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\temB7EC.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{E6950302-61F0-4FEB-97DB-855E30D4A991}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StagingInfo\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\PackageState\S-1-5-21-1336749127-99101324-1432799918-1000\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2816` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7540` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8024` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8064` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8096` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8112` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8136` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NotepadPlusPlus_2247w0b46hfww!NotepadPlusPlus` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\S-1-15-2-2557016000-3416274266-3014759505-2624777461-3676268001-1533065058-806985695` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\notepadplusplus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-In-Block` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-Out-Block` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

### npp / purge (13 missed)

- `P:C:\ProgramData\Microsoft\Windows\AppRepository\4618cfc9-8253-46bc-b94d-6be423bb7531_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\temB7EC.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2816` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7540` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8024` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8064` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8096` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8112` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8136` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

### 7zip / bcu (9 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2548` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3016` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3272` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4080` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4772` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7236` [leftover]

### 7zip / purge (10 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2548` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3016` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3272` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4080` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4772` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7236` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\7-Zip` [leftover]

