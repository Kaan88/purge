# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 1 | 837 | 1.1% | 0.7% | 0.6% | 1.1% | 0.7% | 0.6% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 8.0% | 0.5% | 2.3% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ff-tbafter | purge | 12 | 837 | 1.1% | 0.7% | 0.6% | 1.1% | 0.7% | 0.6% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| ff-tbafter | purge | 2/25 8.0% | 3/593 0.5% | 4/177 2.3% | 0/42 0.0% |

## Truth labels and ambient removal

- **ff-tbafter**: ambient=705, kept_owner=31, leftover=836, rig=1, user_data=1; ambient: f0-null1 removed 334, f0-null2 removed 260, f0-null3 removed 478

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ff-tbafter | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

None.

### (2) unticked user data

- ff-tbafter / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

### (3) replaced_value

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### ff-tbafter / purge (828 missed)

- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0152.10024.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0158.9236.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_015808_9236-1948.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_10_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\b87d0ded-120c-4d4c-bb20-7010e9c750c1.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctBF87.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctC01B.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\f8f05350c84c9d76.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C774119C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\AppID\{D3A3C27F-7AC1-4DC6-990F-4D84DE4C2268}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{29F458BE-8866-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{D3A3C27F-7AC1-4DC6-990F-4D84DE4C2268}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `K:HKLM\SOFTWARE\Classes\MozillaMapi` [leftover]
- `K:HKLM\SOFTWARE\Classes\MozillaMapi.1` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Data\ef` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Data\f0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Index\ActivationKey\7rcqhjsw9vbsjmsjw38nxbmyen90sfxg4wvad9jwdy9h98dj3da0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Index\ActivationKey\ww7p4q6zh3ftd6cffbjtv494p1w581v4e1sx017wha90hcaa12e0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Data\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\ExtensionAndName\2eb^com.microsoft.windows.ai.actions` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\Name\com.microsoft.windows.ai.actions\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\d2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\d2^App` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ea` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2eb` [leftover]

