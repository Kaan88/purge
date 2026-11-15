# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 5 | 2073 | 18.5% | 17.6% | 1.6% | 18.5% | 17.6% | 1.6% | 100.0% | 3 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 11.0% | 46.3% | 5.5% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox-tb | purge | 14 | 64 | 14.1% | 9.4% | 7.8% | 14.1% | 9.4% | 7.8% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |
| vscode | purge | 139 | 391 | 35.0% | 35.0% | 0.0% | 35.0% | 35.0% | 0.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 137 | 393 | 34.4% | 34.4% | 0.0% | 34.4% | 34.4% | 0.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 137 | 0 | 0 | 0 | 0 | 0 |
| git | purge | 4 | 964 | 0.3% | 0.3% | 0.0% | 0.3% | 0.3% | 0.0% | - | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 3 | 1 | 0 | 0 | 0 | 0 |
| npp | purge | 3 | 261 | 8.8% | 8.8% | 0.0% | 8.8% | 8.8% | 0.0% | - | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox-tb | purge | 2/16 12.5% | 3/10 30.0% | 4/16 25.0% | 0/22 0.0% |
| vscode | purge | 1/17 5.9% | 136/169 80.5% | 0/165 0.0% | 0/40 0.0% |
| vscode-user | purge | 1/19 5.3% | 134/166 80.7% | 0/168 0.0% | 0/40 0.0% |
| git | purge | 0/41 0.0% | 1/671 0.1% | 2/190 1.1% | 0/62 0.0% |
| npp | purge | 5/16 31.2% | 16/40 40.0% | 2/165 1.2% | 0/40 0.0% |

## Truth labels and ambient removal

- **firefox-tb**: ambient=300, kept_owner=2, leftover=63, rig=2, user_data=1; ambient: f0-null1 removed 232, f0-null2 removed 214, f0-null3 removed 231
- **vscode**: ambient=1001, kept_owner=0, leftover=389, rig=1, user_data=2; ambient: f0-null1 removed 247, f0-null2 removed 229, f0-null3 removed 240
- **vscode-user**: ambient=1016, kept_owner=0, leftover=391, rig=1, user_data=2; ambient: f0-null1 removed 256, f0-null2 removed 235, f0-null3 removed 251
- **git**: ambient=425, kept_owner=1, leftover=964, rig=1, user_data=0; ambient: f0-null1 removed 293, f0-null2 removed 218, f0-null3 removed 291
- **npp**: ambient=1066, kept_owner=0, leftover=261, rig=1, user_data=0; ambient: f0-null1 removed 289, f0-null2 removed 222, f0-null3 removed 282

## Danger items

- git / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2; replaced: before 'C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Oracle VirtualBox Guest Additions\Uninstall.lnk | C:\Program Files\Oracle\VirtualBox Guest A', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Git\Git Bash.lnk | C:\Program Files\Git\git-bash.exe | --cd-to-home'
- npp / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2; replaced: before 'C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Oracle VirtualBox Guest Additions\Uninstall.lnk | C:\Program Files\Oracle\VirtualBox Guest A', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk | C:\Program Files\Notepad++\notepad++.exe'

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox-tb | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| vscode | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| vscode-user | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| git | purge | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| npp | purge | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

None.

### (2) unticked user data

- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 
- vscode / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 
- vscode-user / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

### (3) replaced_value

- git / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2; replaced: before 'C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Oracle VirtualBox Guest Additions\Uninstall.lnk | C:\Program Files\Oracle\VirtualBox Guest A', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Git\Git Bash.lnk | C:\Program Files\Git\git-bash.exe | --cd-to-home'
- npp / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2; replaced: before 'C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Oracle VirtualBox Guest Additions\Uninstall.lnk | C:\Program Files\Oracle\VirtualBox Guest A', after 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk | C:\Program Files\Notepad++\notepad++.exe'

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox-tb / purge (55 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\29b3ae0dc31337025c49900c96037d42504ccf62` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\d3ba7cd9-cd6a-4ade-b6eb-b3859fa659a9.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|Hardware` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMDiscoveryTTL` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMID` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|SCMID` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|UpdateTimer` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\IsolationSession|Start` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|IrisActionCreatives` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|_now_` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|Data` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\Metadata|IrisUpdateTimestamp` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.YourPhone_8wekyb3d8bbwe\HAM\AUI\App\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.RulesEngine\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.RulesEngine\V1\LU|PTT` [leftover]

### vscode / purge (254 missed)

- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x86__8wekyb3d8bbwe\S-1-5-21-1871224937-2691627691-3762806239-1000.pckgdep` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.VCLibs.140.00_14.0.33519.0_x86__8wekyb3d8bbwe\S-1-5-21-1871224937-2691627691-3762806239-1000.pckgdep` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794711024.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\ShowPicturesOnArrival` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\WPD` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxcontent!showshowpicturesonarrival` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxdevice!wpd` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Tuning` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\wp-autoplay` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.jxl` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.ptx` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.pxn` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.svg` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX77zsthmbxzqveyvr5gqhcfpnd7mfnd5j` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX7tycjjv3satx1c8myac3gpn9ktrwns6b` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXnjayypjpx6dtabtjqtt76hhmg5nsz5nm` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXsywsp6kb3dx2vqg7qaqkbc26sn1pbd28` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXwwaj365vh56qsq113kc3zrs1rvk43s1k` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x86__8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\Microsoft.VCLibs.140.00_14.0.33519.0_x86__8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` [leftover] (partial)
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\wp-autoplay` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.avif` [leftover]

### vscode-user / purge (258 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\328cf76d582cda5b9a1c0a96565f79940c7c06eb` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794711447.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794711474.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\ShowPicturesOnArrival` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\WPD` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxcontent!showshowpicturesonarrival` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxdevice!wpd` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Tuning` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\wp-autoplay` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.jxl` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.ptx` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.pxn` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.svg` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX77zsthmbxzqveyvr5gqhcfpnd7mfnd5j` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX7tycjjv3satx1c8myac3gpn9ktrwns6b` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXnjayypjpx6dtabtjqtt76hhmg5nsz5nm` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXsywsp6kb3dx2vqg7qaqkbc26sn1pbd28` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXwwaj365vh56qsq113kc3zrs1rvk43s1k` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` [leftover] (partial)
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\wp-autoplay` [leftover]

### git / purge (961 missed)

- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\Codecs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0303.7464.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0303.7464.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0303.4440.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0303.4440.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-15.0303.4440.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-15.0303.4440.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0303.7800.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0303.7800.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\telemetryCache.otc-shm` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\telemetryCache.otc-wal` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\CxP.db-shm` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\CxP.db-wal` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\OCSI.db-shm` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\OCSI.db-wal` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\SafeDelete.db-shm` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\SafeDelete.db-wal` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\SyncEngineDatabase.db-shm` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\settings\Personal\SyncEngineDatabase.db-wal` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-15_030336_4440-8048.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Update_2026-11-15_030334_7800-7840.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\ddfdec91220a9dd469b42b9a5caac8a18fa06ebe[1].xml` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-A9688JMALV-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctDD7F.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX77zsthmbxzqveyvr5gqhcfpnd7mfnd5j` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX7tycjjv3satx1c8myac3gpn9ktrwns6b` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXnjayypjpx6dtabtjqtt76hhmg5nsz5nm` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXsywsp6kb3dx2vqg7qaqkbc26sn1pbd28` [leftover]

### npp / purge (238 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem2423.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\ShowPicturesOnArrival` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers\WPD` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxcontent!showshowpicturesonarrival` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\dsd9eksajf9re3669zh5z2jykhws2jy42gypaqjh1qe66nyek1hg!desktopappxdevice!wpd` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Notepad++` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\wp-autoplay` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.jxl` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.ptx` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.pxn` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\.svg` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX77zsthmbxzqveyvr5gqhcfpnd7mfnd5j` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppX7tycjjv3satx1c8myac3gpn9ktrwns6b` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXnjayypjpx6dtabtjqtt76hhmg5nsz5nm` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXsywsp6kb3dx2vqg7qaqkbc26sn1pbd28` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\AppXwwaj365vh56qsq113kc3zrs1rvk43s1k` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\wp-autoplay` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.avif` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.bmp` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.dib` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.gif` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.heic` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.heif` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.hif` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.ico` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.jfif` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.jpe` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.jpeg` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.jpg` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.jxl` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.jxr` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts|AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre_.png` [leftover]

