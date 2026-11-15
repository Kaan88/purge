# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 5 | 412 | 5.0% | 5.0% | 5.0% | 5.0% | 5.0% | 5.0% | 100.0% | 4 | 0 | 0 | 1 | 0 | 0 | 0.0% | 8.8% | 0.0% | 0.0% |
| purge | 7 | 639 | 40.5% | 37.9% | 26.7% | 40.5% | 37.9% | 26.7% | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 17.3% | 45.7% | 31.7% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vscode | bcu | 202 | 161 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 202 | 0 | 0 |
| vscode | purge | 139 | 161 | 85.1% | 85.1% | 83.9% | 85.1% | 85.1% | 83.9% | 100.0% | 0 | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 147 | 201 | 72.1% | 71.6% | 70.6% | 72.1% | 71.6% | 70.6% | 100.0% | 0 | 0 | 0 | 0 | 0 | 147 | 0 | 0 | 0 | 0 | 0 |
| git | bcu | 14 | 162 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 |
| git | purge | 4 | 162 | 2.5% | 2.5% | 2.5% | 2.5% | 2.5% | 2.5% | 100.0% | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| firefox | bcu | 17 | 46 | 10.9% | 10.9% | 10.9% | 10.9% | 10.9% | 10.9% | 100.0% | 4 | 0 | 0 | 1 | 0 | 9 | 0 | 0 | 8 | 0 | 0 |
| firefox | purge | 20 | 46 | 21.7% | 15.2% | 10.9% | 21.7% | 15.2% | 10.9% | 100.0% | 5 | 0 | 0 | 0 | 0 | 20 | 0 | 0 | 0 | 0 | 0 |
| firefox-tb | purge | 14 | 26 | 34.6% | 23.1% | 19.2% | 34.6% | 23.1% | 19.2% | 100.0% | 1 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| npp | bcu | 10 | 34 | 2.9% | 2.9% | 2.9% | 2.9% | 2.9% | 2.9% | 100.0% | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 9 | 0 | 0 |
| npp | purge | 2 | 34 | 67.6% | 67.6% | 0.0% | 67.6% | 67.6% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| 7zip | bcu | 20 | 9 | 11.1% | 11.1% | 11.1% | 11.1% | 11.1% | 11.1% | 100.0% | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 19 | 0 | 0 |
| 7zip | purge | 0 | 9 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| vscode | bcu | 0/13 0.0% | 0/146 0.0% | 0/2 0.0% | 0/0 - |
| vscode | purge | 1/13 7.7% | 136/146 93.2% | 0/2 0.0% | 0/0 - |
| vscode-user | purge | 1/16 6.2% | 144/162 88.9% | 0/16 0.0% | 0/7 0.0% |
| git | bcu | 0/21 0.0% | 0/14 0.0% | 0/21 0.0% | 0/106 0.0% |
| git | purge | 0/21 0.0% | 2/14 14.3% | 2/21 9.5% | 0/106 0.0% |
| firefox | bcu | 0/7 0.0% | 5/20 25.0% | 0/7 0.0% | 0/12 0.0% |
| firefox | purge | 2/7 28.6% | 4/20 20.0% | 4/7 57.1% | 0/12 0.0% |
| firefox-tb | purge | 2/7 28.6% | 3/11 27.3% | 4/7 57.1% | 0/1 0.0% |
| npp | bcu | 0/10 0.0% | 1/21 4.8% | 0/3 0.0% | 0/0 - |
| npp | purge | 5/10 50.0% | 16/21 76.2% | 2/3 66.7% | 0/0 - |
| 7zip | bcu | 0/2 0.0% | 1/7 14.3% | 0/0 - | 0/0 - |
| 7zip | purge | 0/2 0.0% | 0/7 0.0% | 0/0 - | 0/0 - |

## Truth labels and ambient removal

- **vscode**: ambient=239, kept_owner=0, leftover=159, rig=0, user_data=2; ambient: r0-null1 removed 152, r0-null2 removed 152, r0-null3 removed 152
- **vscode-user**: ambient=242, kept_owner=0, leftover=199, rig=0, user_data=2; ambient: r0-null1 removed 150, r0-null2 removed 150, r0-null3 removed 149
- **git**: ambient=146, kept_owner=0, leftover=162, rig=1, user_data=0; ambient: r0-null1 removed 87, r0-null2 removed 110, r0-null3 removed 87
- **firefox**: ambient=258, kept_owner=0, leftover=45, rig=1, user_data=1; ambient: r0-null1 removed 164, r0-null2 removed 164, r0-null3 removed 162
- **firefox-tb**: ambient=165, kept_owner=2, leftover=25, rig=0, user_data=1; ambient: r0-null1 removed 132, r0-null2 removed 135, r0-null3 removed 134
- **npp**: ambient=209, kept_owner=0, leftover=34, rig=0, user_data=0; ambient: r0-null1 removed 117, r0-null2 removed 121, r0-null3 removed 118
- **7zip**: ambient=168, kept_owner=0, leftover=9, rig=0, user_data=0; ambient: r0-null1 removed 146, r0-null2 removed 148, r0-null3 removed 146

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### vscode / bcu (161 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794570732.log` [leftover]
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

### vscode / purge (24 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794570732.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1348` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1448` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1588` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2572` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4448` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6416` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7736` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]

### vscode-user / purge (56 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Inbound Download Manager\window-placement.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794571062.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794571088.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\f18460fded109990.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1016` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1688` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2888` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3308` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6296` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7904` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8708` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Phone\ShellUI\WindowSizing\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A006C` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\windows.immersivecontrolpanel_cw5n1h2txyewy\ApplicationFrame` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\windows.immersivecontrolpanel_cw5n1h2txyewy\HAM` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\windows.immersivecontrolpanel_cw5n1h2txyewy\PersistedTitleBarData` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\windows.immersivecontrolpanel_cw5n1h2txyewy\SplashScreen` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Users\tester\AppData\Local\Programs\Inbound Download Manager\app\DownloadManager.Host.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\Volatile|windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|jvaqbjf.vzzrefvirpbagebycnary_pj5a1u2gklrjl!zvpebfbsg.jvaqbjf.vzzrefvirpbagebycnary` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|P:\Hfref\grfgre\NccQngn\Ybpny\Cebtenzf\Vaobhaq Qbjaybnq Znantre\ncc\QbjaybnqZnantre.Qrfxgbc.JvaHV.rkr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{R7876P5S-OP5R-45O7-79N5-Q63R7P98PN2R}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count|{N77S5Q77-2R2O-44P3-N6N2-NON601054N51}\Vaobhaq Qbjaybnq Znantre.yax` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{44090B31-CDF9-4AD1-8182-DB5DA3627974} {7F9185B0-CB92-43C5-80A9-92277A4F7B54} 0xFFFF` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{C7657C4A-9F68-40FA-A4DF-96BC08EB3551} {E357FCCD-A995-4576-B01F-234630154E96} 0xFFFF` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\windows.immersivecontrolpanel_cw5n1h2txyewy|WasEverActivated` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\AppData\Local\Programs\Inbound Download Manager\app\DownloadManager.Desktop.WinUI.exe.ApplicationCompany` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\AppData\Local\Programs\Inbound Download Manager\app\DownloadManager.Desktop.WinUI.exe.FriendlyAppName` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Windows\System32\appresolver.dll.ApplicationCompany` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Windows\System32\appresolver.dll.FriendlyAppName` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.Jvaqbjf.FgnegZrahRkcrevraprUbfg_pj5a1u2gklrjl!Ncc` [leftover]

### git / bcu (162 missed)

- `P:C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\4772_13439045029302277_4772.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\5656_13439045029466860_5656.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\7340_13439045032061088_7340.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\7460_13439045029500391_7460.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeCore\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeCore\Optimized\157.0.4341.57.manifest` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\{78B37294-AA80-4E5F-A64A-948E5800E03F}` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\{EAE6F728-FD20-4216-8EBC-65CAE9F1364A}` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeWebView\Application\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeWebView\Application\SetupMetrics\7856_13439045051733835_7856.pma` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-G9QC3KYYGD-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{CD6EC556-4122-431B-B2CB-CDD2965F2A26}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{E795A3E3-B3E2-4957-8E72-B618117992D7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\sh_auto_file` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\96` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\97` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\1\96` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\1\97` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\1^31\97` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\1^32\96` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Reporting\RebootWatch` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1048` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1972` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules|C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.57\msedge_wer.dll` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}|InstallerProgress` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|DownloadProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|DownloadTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|InstallProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|InstallTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}|InstallerProgress` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|DownloadProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|DownloadTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|InstallProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|InstallTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\UsageStats\Daily\Counts|cdp_installer_pick_patch` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\UsageStats\Daily\Counts|client_another_update_in_progress` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{6C5A1F13-D115-4523-ABFD-DD11B648F364}` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{9A3F73F0-85FA-481B-A38D-2B7D60C68C49}` [leftover]

### git / purge (158 missed)

- `P:C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\4772_13439045029302277_4772.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\5656_13439045029466860_5656.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\7340_13439045032061088_7340.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\7460_13439045029500391_7460.pma` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeCore\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeCore\Optimized\157.0.4341.57.manifest` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Download\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\{78B37294-AA80-4E5F-A64A-948E5800E03F}` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\{EAE6F728-FD20-4216-8EBC-65CAE9F1364A}` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeWebView\Application\157.0.4341.57` [leftover]
- `P:C:\Program Files (x86)\Microsoft\EdgeWebView\Application\SetupMetrics\7856_13439045051733835_7856.pma` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-G9QC3KYYGD-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{CD6EC556-4122-431B-B2CB-CDD2965F2A26}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{E795A3E3-B3E2-4957-8E72-B618117992D7}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\96` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\97` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\1\96` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\1\97` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\1^31\97` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\1^32\96` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Reporting\RebootWatch` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1048` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1972` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules|C:\Program Files (x86)\Microsoft\Edge\Application\157.0.4341.57\msedge_wer.dll` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}|InstallerProgress` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|DownloadProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|DownloadTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|InstallProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\CurrentState|InstallTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}|InstallerProgress` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|DownloadProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|DownloadTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|InstallProgressPercent` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}\CurrentState|InstallTimeRemainingMs` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\UsageStats\Daily\Counts|cdp_installer_pick_patch` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\UsageStats\Daily\Counts|client_another_update_in_progress` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{6C5A1F13-D115-4523-ABFD-DD11B648F364}` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{9A3F73F0-85FA-481B-A38D-2B7D60C68C49}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]

### firefox / bcu (41 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Mozilla` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\70e56f79-88bd-4ce8-98fd-988008fdf888.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Mozilla` [user_data] (partial)
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{42051705-EFBF-4805-BAC0-0694133DBEEE}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{BB420D80-F6A5-4ABF-A113-3D31E7D1BE61}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4152` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4612` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5892` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7448` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7556` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7760` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7796` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` [leftover] (partial)
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` [leftover] (partial)
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{C81AF98B-CD97-4E6D-AB85-57D38575EEBE}` [leftover]
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
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|ECSExpiryConfig` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|ECSExpiryTime` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|LastECSETag` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|LastStartedAU` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\UsageStats\Daily|LastTransmission` [leftover]

### firefox / purge (36 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\70e56f79-88bd-4ce8-98fd-988008fdf888.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\CLSID\{42051705-EFBF-4805-BAC0-0694133DBEEE}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{BB420D80-F6A5-4ABF-A113-3D31E7D1BE61}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4152` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4612` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5892` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7448` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7556` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7760` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7796` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
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
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|ECSExpiryConfig` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|ECSExpiryTime` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|LastECSETag` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate|LastStartedAU` [leftover]
- `C:HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\UsageStats\Daily|LastTransmission` [leftover]

### firefox-tb / purge (17 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\102f8c75-07b1-4c9b-a050-429d8de08c27.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2872` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3760` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4056` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4932` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6588` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8340` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]

### npp / bcu (33 missed)

- `P:C:\Program Files\WindowsApps\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\6bead1fe-635c-4d93-b56b-f9d1f09e8bbb_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem800.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{E6950302-61F0-4FEB-97DB-855E30D4A991}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StagingInfo\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\PackageState\S-1-5-21-1336749127-99101324-1432799918-1000\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3120` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3860` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7320` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7868` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7964` [leftover]
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

### npp / purge (11 missed)

- `P:C:\ProgramData\Microsoft\Windows\AppRepository\6bead1fe-635c-4d93-b56b-f9d1f09e8bbb_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem800.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3120` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3860` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7320` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7868` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7964` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

### 7zip / bcu (8 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1644` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5152` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5580` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6252` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7204` [leftover]

### 7zip / purge (9 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1644` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5152` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5580` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6252` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7204` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\7-Zip` [leftover]

