# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 2 | 73 | 26.8% | 10.9% | 9.7% | 17.7% | 10.9% | 9.7% | 100.0% | 2 | 7 | 0 | 0 | 2 | 2 | 40.8% | 6.2% | 61.7% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ff-esr | purge | 21 | 44 | 43.2% | 11.4% | 9.1% | 25.0% | 11.4% | 9.1% | 100.0% | 0 | 7 | 0 | 0 | 2 | 12 | 7 | 0 | 0 | 2 | 0 |
| vlc | purge | 6 | 29 | 10.3% | 10.3% | 10.3% | 10.3% | 10.3% | 10.3% | 100.0% | 2 | 0 | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| ff-esr | purge | 8/13 61.5% | 1/8 12.5% | 10/12 83.3% | 0/11 0.0% |
| vlc | purge | 1/5 20.0% | 0/13 0.0% | 2/5 40.0% | 0/6 0.0% |

## Truth labels and ambient removal

- **ff-esr**: ambient=86, kept_owner=3, leftover=38, rig=1, user_data=6; ambient: r0-null1 removed 59, r0-null2 removed 62, r0-null3 removed 60
- **vlc**: ambient=171, kept_owner=0, leftover=29, rig=0, user_data=0; ambient: r0-null1 removed 142, r0-null2 removed 146, r0-null3 removed 141

## Danger items

- ff-esr / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-esr / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-esr / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 223 entries left inside (102 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\3tc8oot3.default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 268 entries left inside (141 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\46d5xsmk.MozillaBackgroundTask-308046B0AF4A39CB-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| ff-esr | purge | 0 | 0 | 7 | 1 | 0 | 0 | 0 |
| vlc | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

- ff-esr / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-esr / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-esr / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (2) unticked user data

- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### ff-esr / purge (25 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\Firefox_S-1-5-21-1336749127-99101324-1432799918-1000_shortcuts.ini` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7600` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7700` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7724` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7784` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\InstallService` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
- `C:HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Usage|SwarmCount` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### vlc / purge (26 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\VLC.EXE-46412408.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\DVD\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\VideoLAN.VLCPlugin.2` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\VLCPlayBlurayOnArrival` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1192` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1308` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1560` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2248` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6536` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7116` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7304` [leftover]
- `K:HKLM\SOFTWARE\MozillaPlugins` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings\482821502890861840` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Ext\Stats` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\PlayBluRayOnArrival|VLCPlayBlurayOnArrival` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\VideoLAN\VLC\vlc.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\IvqrbYNA\IYP\iyp.rkr` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|SequenceNumber` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Control Panel\NotifyIconSettings|UIOrderList` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|State` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|UpdateTimer` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

