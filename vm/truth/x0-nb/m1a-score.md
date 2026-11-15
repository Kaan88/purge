# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 5 | 519 | 43.2% | 41.9% | 2.9% | 43.2% | 41.9% | 2.9% | 100.0% | 3 | 2 | 0 | 0 | 0 | 0 | 13.4% | 49.0% | 22.2% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox-tb | purge | 14 | 44 | 20.5% | 13.6% | 11.4% | 20.5% | 13.6% | 11.4% | 100.0% | 1 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| vscode | purge | 139 | 194 | 70.6% | 70.6% | 0.0% | 70.6% | 70.6% | 0.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 138 | 199 | 68.3% | 68.3% | 0.0% | 68.3% | 68.3% | 0.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 138 | 0 | 0 | 0 | 0 | 0 |
| git | purge | 4 | 34 | 8.8% | 8.8% | 2.9% | 8.8% | 8.8% | 2.9% | 100.0% | 0 | 1 | 0 | 0 | 0 | 3 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 3 | 48 | 47.9% | 47.9% | 0.0% | 47.9% | 47.9% | 0.0% | - | 0 | 1 | 0 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox-tb | purge | 2/13 15.4% | 3/19 15.8% | 4/9 44.4% | 0/3 0.0% |
| vscode | purge | 1/31 3.2% | 136/158 86.1% | 0/3 0.0% | 0/2 0.0% |
| vscode-user | purge | 1/33 3.0% | 135/160 84.4% | 0/3 0.0% | 0/3 0.0% |
| git | purge | 0/9 0.0% | 1/18 5.6% | 2/6 33.3% | 0/1 0.0% |
| npp | purge | 5/11 45.5% | 16/30 53.3% | 2/6 33.3% | 0/1 0.0% |

## Truth labels and ambient removal

- **firefox-tb**: ambient=400, kept_owner=2, leftover=43, rig=1, user_data=1; ambient: f0-null1 removed 341, f0-null2 removed 267, f0-null3 removed 330
- **vscode**: ambient=750, kept_owner=0, leftover=192, rig=1, user_data=2; ambient: f0-null1 removed 358, f0-null2 removed 291, f0-null3 removed 583
- **vscode-user**: ambient=756, kept_owner=0, leftover=197, rig=1, user_data=2; ambient: f0-null1 removed 367, f0-null2 removed 309, f0-null3 removed 618
- **git**: ambient=286, kept_owner=0, leftover=34, rig=1, user_data=0; ambient: f0-null1 removed 254, f0-null2 removed 242, f0-null3 removed 232
- **npp**: ambient=408, kept_owner=0, leftover=48, rig=1, user_data=0; ambient: f0-null1 removed 316, f0-null2 removed 244, f0-null3 removed 297

## Danger items

- git / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2
- npp / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| firefox-tb | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| vscode | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| vscode-user | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| git | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

- git / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2
- npp / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2

### (2) unticked user data

- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 
- vscode / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 
- vscode-user / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox-tb / purge (35 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_13_17_45_22.etl` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\uNLQAacR8UapVx2A.0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1620` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2904` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3616` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3644` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5140` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5328` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6364` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6748` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7728` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9356` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]

### vscode / purge (57 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1451.7972.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1451.9692.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1452.8476.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1452.8476.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1452.8476.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1452.8476.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_145204_8476-2172.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_145156_7972-2380.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_145156_9692-1828.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794581357.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct1309.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct2B81.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctB66.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctB67.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1536` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2132` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2272` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2404` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4056` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4392` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6092` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6620` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6656` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6660` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8864` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9516` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9592` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9920` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Tuning` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]

### vscode-user / purge (63 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_13_18_4_14.etl` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1503.4000.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1503.9860.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1503.6336.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1503.6336.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1503.6336.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1503.6336.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_150347_6336-10016.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_150339_4000-1820.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_150339_9860-3028.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794581919.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794581951.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct57F6.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct57F7.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct5FB8.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct7811.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\p3seaKplw0aXoEXV.0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1316` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2896` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4144` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4620` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4736` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6000` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6440` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6448` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6512` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7288` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\756` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7748` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8532` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9036` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9924` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!WMSS` [leftover]

### git / purge (31 missed)

- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-92I6LETPS0-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1216` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1356` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3048` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4228` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5796` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6456` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6464` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6500` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7600` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9628` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9716` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~https://gitforwindows.org/faq` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Git` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]

### npp / purge (25 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\d63e4fb5-e7a1-4953-847d-4213ce1725eb_S-1-5-21-1871224937-2691627691-3762806239-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\temAA3B.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2188` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2684` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3364` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5700` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6388` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6496` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6648` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6684` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7268` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\740` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7876` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9248` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9572` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Notepad++` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

