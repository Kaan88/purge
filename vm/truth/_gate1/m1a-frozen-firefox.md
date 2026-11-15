# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 1 | 24 | 20.8% | 20.8% | 20.8% | 20.8% | 20.8% | 20.8% | 100.0% | 4 | 0 | 0 | 1 | 0.0% | 50.0% | 0.0% | - |
| purge | 1 | 24 | 45.8% | 33.3% | 20.8% | 45.8% | 33.3% | 20.8% | 100.0% | 4 | 0 | 0 | 0 | 42.9% | 50.0% | 42.9% | - |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | hit | danger | ambient | gone | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| firefox | purge | 23 | 24 | 45.8% | 33.3% | 20.8% | 45.8% | 33.3% | 20.8% | 100.0% | 4 | 0 | 0 | 0 | 22 | 0 | 0 | 1 | 0 |
| firefox | bcu | 17 | 24 | 20.8% | 20.8% | 20.8% | 20.8% | 20.8% | 20.8% | 100.0% | 4 | 0 | 0 | 1 | 9 | 0 | 0 | 8 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| firefox | purge | 3/7 42.9% | 5/10 50.0% | 3/7 42.9% | 0/0 - |
| firefox | bcu | 0/7 0.0% | 5/10 50.0% | 0/7 0.0% | 0/0 - |

## Truth labels and ambient removal

- **firefox**: ambient=103, kept_owner=0, leftover=23, rig=0, user_data=1; ambient: null1 removed 72, null2 removed 73, null3 removed 71

## Danger items

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### firefox / purge (13 missed)

- `P:C:\Users\tester\AppData\Local\Temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{AC21D679-A9C1-47A0-B96F-A0625A9EE822}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]

### firefox / bcu (19 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Mozilla` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Mozilla` [user_data] (partial)
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` [leftover] (partial)
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` [leftover] (partial)
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{AC21D679-A9C1-47A0-B96F-A0625A9EE822}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]

