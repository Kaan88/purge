# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 1 | 813 | 0.6% | 0.6% | 0.6% | 0.6% | 0.6% | 0.6% | 100.0% | 4 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0.0% | 0.9% | 0.0% | 0.0% |
| purge | 3 | 1700 | 9.5% | 2.8% | 2.2% | 5.8% | 2.8% | 2.2% | 100.0% | 6 | 0 | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 16.6% | 5.2% | 20.0% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | bcu | 17 | 813 | 0.6% | 0.6% | 0.6% | 0.6% | 0.6% | 0.6% | 100.0% | 4 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 9 | 0 | 0 | 8 | 0 | 0 |
| firefox | purge | 20 | 813 | 1.2% | 0.9% | 0.6% | 1.2% | 0.9% | 0.6% | 100.0% | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 20 | 0 | 0 | 0 | 0 | 0 |
| firefox-tb | purge | 14 | 814 | 1.1% | 0.7% | 0.6% | 1.1% | 0.7% | 0.6% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| ff-esr | purge | 19 | 73 | 26.0% | 6.8% | 5.5% | 15.1% | 6.8% | 5.5% | 100.0% | 0 | 0 | 7 | 7 | 0 | 0 | 0 | 0 | 12 | 7 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox | bcu | 0/18 0.0% | 5/578 0.9% | 0/175 0.0% | 0/42 0.0% |
| firefox | purge | 2/18 11.1% | 4/578 0.7% | 4/175 2.3% | 0/42 0.0% |
| firefox-tb | purge | 2/22 9.1% | 3/574 0.5% | 4/175 2.3% | 0/43 0.0% |
| ff-esr | purge | 8/27 29.6% | 1/7 14.3% | 10/18 55.6% | 0/21 0.0% |

## Truth labels and ambient removal

- **firefox**: ambient=537, kept_owner=0, leftover=812, rig=2, user_data=1; ambient: f0-null1 removed 324, f0-null2 removed 252, f0-null3 removed 321
- **firefox-tb**: ambient=696, kept_owner=2, leftover=813, rig=2, user_data=1; ambient: f0-null1 removed 264, f0-null2 removed 261, f0-null3 removed 511
- **ff-esr**: ambient=480, kept_owner=3, leftover=67, rig=2, user_data=6; ambient: f0-null1 removed 189, f0-null2 removed 186, f0-null3 removed 429

## Danger items

- ff-esr / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-esr / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-esr / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Blocked) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Blocked) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | bcu | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| firefox | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| firefox-tb | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| ff-esr | purge | 0 | 0 | 7 | 1 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

- firefox / bcu: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Safe, preselected) hit - 

### (2) unticked danger

- ff-esr / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-esr / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-esr / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Blocked, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Blocked, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (2) unticked user data

- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Likely, Quarantine) hit - 
- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 
- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Likely, Quarantine) hit - 
- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Blocked, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

### (3) replaced_value

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox / bcu (808 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_15_9_18_26.etl` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Mozilla` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\b364a82f-668f-48be-895c-6e7fb84d279f.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Mozilla` [user_data] (partial)
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\dynrespri.7db` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\3EngPWNY7Eu+WTS9.0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Data\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\ExtensionAndName\2eb^com.microsoft.windows.ai.actions` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\Name\com.microsoft.windows.ai.actions\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\d2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\d2^App` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ea` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2eb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ec` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ed` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ee` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ef` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f1` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f3` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f4` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f5` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f6` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f7` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Application\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appExtension` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appService` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.autoPlayHandler` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileExplorerContextMenus` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileTypeAssociation` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.protocol` [leftover]

### firefox / purge (803 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_15_9_18_26.etl` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\b364a82f-668f-48be-895c-6e7fb84d279f.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\dynrespri.7db` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\3EngPWNY7Eu+WTS9.0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Data\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\ExtensionAndName\2eb^com.microsoft.windows.ai.actions` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\Name\com.microsoft.windows.ai.actions\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\d2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\d2^App` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ea` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2eb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ec` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ed` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ee` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ef` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f1` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f3` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f4` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f5` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f6` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f7` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Application\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appExtension` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appService` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.autoPlayHandler` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileExplorerContextMenus` [leftover]

### firefox-tb / purge (805 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\073b77dd2d7daca769ceb3f37810a8ba2172a34f` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\f3774236cb631dbfe816ad61cab598b7ba0167ec` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x86__8wekyb3d8bbwe\S-1-5-21-1871224937-2691627691-3762806239-1000.pckgdep` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.VCLibs.140.00_14.0.33519.0_x86__8wekyb3d8bbwe\S-1-5-21-1871224937-2691627691-3762806239-1000.pckgdep` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0627.1096.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_062758_1096-9084.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\06cf5660-9361-4080-88c4-aa835fb5db0a.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct9B4D.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Data\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\ExtensionAndName\2eb^com.microsoft.windows.ai.actions` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\Name\com.microsoft.windows.ai.actions\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\d2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\d2^App` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ea` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2eb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ec` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ed` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ee` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ef` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f1` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f3` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f4` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f5` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f6` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f7` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Application\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appExtension` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appService` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.autoPlayHandler` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileExplorerContextMenus` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileTypeAssociation` [leftover]

### ff-esr / purge (54 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\c9a85331c5be5eb54c61ee3ae680fcc8862fbb2c` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\cb394a94b5645cd9a67827515d1dd906671021ca` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\Firefox_S-1-5-21-1871224937-2691627691-3762806239-1000_shortcuts.ini` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0634.3764.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_063437_3764-4712.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\c83bd665-edb9-4e9a-8e7a-aa264940d3a0.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctD746.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|Hardware` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMDiscoveryTTL` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMID` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|SCMID` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|IrisActionCreatives` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|_now_` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|Data` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\Metadata|IrisUpdateTimestamp` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.YourPhone_8wekyb3d8bbwe\HAM\AUI\App\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.RulesEngine\V1\LU|PCT` [leftover]

