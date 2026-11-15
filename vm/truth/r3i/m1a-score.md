# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 1 | 27 | 18.5% | 18.5% | 18.5% | 18.5% | 18.5% | 18.5% | 100.0% | 4 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0.0% | 45.5% | 0.0% | 0.0% |
| purge | 2 | 51 | 37.3% | 25.5% | 19.7% | 37.3% | 25.5% | 19.7% | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 31.0% | 43.2% | 53.6% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | bcu | 17 | 27 | 18.5% | 18.5% | 18.5% | 18.5% | 18.5% | 18.5% | 100.0% | 4 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 9 | 0 | 0 | 8 | 0 | 0 |
| firefox | purge | 20 | 27 | 37.0% | 25.9% | 18.5% | 37.0% | 25.9% | 18.5% | 100.0% | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 20 | 0 | 0 | 0 | 0 | 0 |
| firefox-tb | purge | 14 | 24 | 37.5% | 25.0% | 20.8% | 37.5% | 25.0% | 20.8% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox | bcu | 0/6 0.0% | 5/11 45.5% | 0/7 0.0% | 0/3 0.0% |
| firefox | purge | 2/6 33.3% | 4/11 36.4% | 4/7 57.1% | 0/3 0.0% |
| firefox-tb | purge | 2/7 28.6% | 3/6 50.0% | 4/8 50.0% | 0/3 0.0% |

## Truth labels and ambient removal

- **firefox**: ambient=229, kept_owner=0, leftover=26, rig=0, user_data=1; ambient: r2-null1 removed 123, r2-null2 removed 192, r2-null3 removed 188
- **firefox-tb**: ambient=174, kept_owner=2, leftover=23, rig=0, user_data=1; ambient: r2-null1 removed 94, r2-null2 removed 137, r2-null3 removed 136

## Danger items

None.

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

### (1) blocking danger

None.

### (1) blocking user data

- firefox / bcu: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Safe, preselected) hit - 

### (2) unticked danger

None.

### (2) unticked user data

- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Likely, Quarantine) hit - 
- firefox / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 
- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Likely, Quarantine) hit - 
- firefox-tb / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

### (3) replaced_value

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox / bcu (22 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Mozilla` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Mozilla` [user_data] (partial)
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` [leftover] (partial)
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` [leftover] (partial)
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{6FA90C2C-8278-4623-B149-32F3BCDBF6DC}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\Defrag|TotalBytesSaved` [leftover]
- `C:HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\FontCache\SystemFontProvider|ConfigExpiration` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|ReportStateTimestamp` [leftover]

### firefox / purge (17 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\Defrag|TotalBytesSaved` [leftover]
- `C:HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\FontCache\SystemFontProvider|ConfigExpiration` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|ReportStateTimestamp` [leftover]

### firefox-tb / purge (15 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\23f672f1-d8d7-4b53-b6de-d337b876af36.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\FontCache\SystemFontProvider|ConfigExpiration` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|ReportStateTimestamp` [leftover]

