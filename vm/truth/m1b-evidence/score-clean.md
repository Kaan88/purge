# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 7 | 152 | 18.1% | 18.1% | 4.8% | 18.1% | 18.1% | 4.8% | 100.0% | 1 | 0 | 4 | 4 | 0 | 0 | 0 | 9 | 7 | 0.0% | 25.0% | 31.4% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 1 | 3 | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python | purge | 3 | 34 | 2.9% | 2.9% | 0.0% | 2.9% | 2.9% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0 |
| python312-with-313 | purge | 6 | 45 | 2.2% | 2.2% | 0.0% | 2.2% | 2.2% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 3 | 1 | 1 | 0 | 0 | 4 | 0 |
| python313-with-312 | purge | 6 | 48 | 2.1% | 2.1% | 0.0% | 2.1% | 2.1% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 3 | 1 | 1 | 0 | 0 | 4 | 0 |
| node | purge | 3 | 4 | 75.0% | 75.0% | 0.0% | 75.0% | 75.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0 |
| vcredist | purge | 2 | 9 | 11.1% | 11.1% | 0.0% | 11.1% | 11.1% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |
| powershell | purge | 2 | 9 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| temurin | purge | 0 | 0 | - | - | - | - | - | - | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| 7zip | purge | 0/2 0.0% | 1/1 100.0% | 0/0 - | 0/0 - |
| python | purge | 0/25 0.0% | 0/0 - | 1/5 20.0% | 0/4 0.0% |
| python312-with-313 | purge | 0/25 0.0% | 0/5 0.0% | 1/10 10.0% | 0/5 0.0% |
| python313-with-312 | purge | 0/25 0.0% | 0/5 0.0% | 1/12 8.3% | 0/6 0.0% |
| node | purge | 0/1 0.0% | 0/0 - | 3/3 100.0% | 0/0 - |
| vcredist | purge | 0/7 0.0% | 0/0 - | 1/2 50.0% | 0/0 - |
| powershell | purge | 0/2 0.0% | 0/6 0.0% | 0/1 0.0% | 0/0 - |
| temurin | purge | 0/0 - | 0/0 - | 0/0 - | 0/0 - |

## Truth labels and ambient removal

- **7zip**: ambient=51, kept_owner=0, leftover=3, rig=0, user_data=0; ambient: m1b-null1 removed 31, m1b-null2 removed 30, m1b-null3 removed 31
- **python**: ambient=133, kept_owner=29, leftover=33, user_data=1; ambient: m1b-null1 removed 89, m1b-null2 removed 90, m1b-null3 removed 49
- **python312-with-313**: ambient=76, kept_owner=42, leftover=44, user_data=1; ambient: m1b-null1 removed 39, m1b-null2 removed 37, m1b-null3 removed 35
- **python313-with-312**: ambient=81, kept_owner=44, leftover=47, user_data=1; ambient: m1b-null1 removed 37, m1b-null2 removed 36, m1b-null3 removed 34
- **node**: ambient=74, leftover=4; ambient: m1b-null1 removed 36, m1b-null2 removed 34, m1b-null3 removed 35
- **vcredist**: ambient=117, leftover=9; ambient: m1b-null1 removed 85, m1b-null2 removed 85, m1b-null3 removed 45
- **powershell**: ambient=150, kept_owner=2, leftover=9; ambient: m1b-null1 removed 38, m1b-null2 removed 35, m1b-null3 removed 37
- **temurin**: ambient=41; ambient: m1b-null1 removed 26, m1b-null2 removed 26, m1b-null3 removed 24

## Danger items

- python / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- python312-with-313 / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- python313-with-312 / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{9b3415f5-afcc-46ea-9954-a8000df10f86}\python-3.13.17-amd64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vcredist / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\ProgramData\Package Cache\{d8bbe9f9-7c5b-42c6-b715-9ee898a2e515}\VC_redist.x64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- python / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (0 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- python312-with-313 / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Python; as a plain delete: covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- python312-with-313 / purge: `K:HKLM\SOFTWARE\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 50 entries left inside (30 existed in snap0), e.g. K:HKLM\SOFTWARE\Python\PythonCore, K:HKLM\SOFTWARE\Python\PythonCore\3.12, K:HKLM\SOFTWARE\Python\PythonCore\3.12\Help; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\Python
- python312-with-313 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` (Blocked) - not empty after the plan's other removals: 4 entries left inside (0 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\IDLE (Python 3.12 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 Manuals (64-bit).lnk
- python312-with-313 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\IDLE (Python 3.13 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13
- python313-with-312 / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Python; as a plain delete: covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- python313-with-312 / purge: `K:HKLM\SOFTWARE\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 50 entries left inside (30 existed in snap0), e.g. K:HKLM\SOFTWARE\Python\PythonCore, K:HKLM\SOFTWARE\Python\PythonCore\3.12, V:HKLM\SOFTWARE\Python\PythonCore\3.12|DisplayName; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\Python
- python313-with-312 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\IDLE (Python 3.12 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12
- python313-with-312 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13` (Blocked) - not empty after the plan's other removals: 4 entries left inside (0 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\IDLE (Python 3.13 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 Manuals (64-bit).lnk

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| python | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python312-with-313 | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python313-with-312 | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| node | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vcredist | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| powershell | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| temurin | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

- python / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` (Blocked, DeleteValue) danger - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- python312-with-313 / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` (Blocked, DeleteValue) danger - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- python313-with-312 / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{9b3415f5-afcc-46ea-9954-a8000df10f86}\python-3.13.17-amd64.exe` (Blocked, DeleteValue) danger - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vcredist / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\ProgramData\Package Cache\{d8bbe9f9-7c5b-42c6-b715-9ee898a2e515}\VC_redist.x64.exe` (Blocked, DeleteValue) danger - deny: Report-only: Background Activity Moderator state belongs to the bam driver.

### (2) unticked user data

None.

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

### (3) replaced_value

None.

## Protected items (protected_correct)

Truth items labelled `kept_owner` or `protected` that the plan does not list or lists only as Protected (band Blocked), over all such items. Listed = a plan item equal to, containing or inside the truth item, whatever its outcome or action. `-` = the app has no such item (not applicable, never a pass).

| app | tool | protected_n | correct | protected_correct |
|---|---|---:|---:|---:|
| 7zip | purge | 0 | 0 | - |
| python | purge | 29 | 29 | 100.0% |
| python312-with-313 | purge | 42 | 42 | 100.0% |
| python313-with-312 | purge | 44 | 44 | 100.0% |
| node | purge | 0 | 0 | - |
| vcredist | purge | 0 | 0 | - |
| powershell | purge | 2 | 2 | 100.0% |
| temurin | purge | 0 | 0 | - |

## Notices (not scored)

`ReportOnly` items that suggest uninstalling a related product (`suggest_uninstall`; ruling 2026-11-18): not an offer and not a listing, so outside every count above. **would be** = how the item would have scored as an ordinary listing.

- python / purge: `K:HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73831AC2-F0E1-4173-9FDB-D07463D7EB80}` suggest uninstall "Python Launcher" (Likely, SYS-BURNDEPS; would be danger: kept_owner K:HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73831AC2-F0E1-4173-9FDB-D07463D7EB80})

## Missed truth items (first 50 per app and tool; full list in the JSON)

### 7zip / purge (2 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]

### python / purge (33 missed)

- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DELF2D3.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191642_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118191903_007_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\97992354503a502a.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\cfa2f398f6b586de.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{D625889B-919B-4230-A59F-7DE717FCB4CC}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

### python312-with-313 / purge (44 missed)

- `P:C:\Program Files\Python312` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` [leftover]
- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL9D7B.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_006_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192453_007_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118192730_007_core_AllUsers.log` [leftover]
- `P:C:\WINDOWS\Installer\{984178D8-5728-48E7-89A1-C3E9A4D5F5DE}` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\Help` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\Idle` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\IdleShortcuts` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\InstalledFeatures` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\PythonPath` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python312\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python312\Doc\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{984178D8-5728-48E7-89A1-C3E9A4D5F5DE}\` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{1FF34E85-B299-4A72-B356-56DA8E37B56A}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|3` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|4` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|5` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment|Path` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

### python313-with-312 / purge (47 missed)

- `P:C:\Program Files\Python313` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13` [leftover]
- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL8000.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193352_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118193629_007_core_AllUsers.log` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-992E9CF7.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-95C4C392.pf` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.13\Help` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.13\Idle` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.13\IdleShortcuts` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.13\PythonPath` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python313\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python313\Doc\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python313\Lib\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{558C4CF1-82E8-4C42-BC91-5F1E96E9C99C}\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{8078A005-EBA5-4E1A-9AAF-EC4693A1D7C3}\` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{B11D202B-9676-4EDF-BC1F-BCA0258BC4B6}\.be\python-3.13.17-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{05SS6476-SOS9-40N2-24Q2-168978RS936Q}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|3` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|4` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|5` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment|Path` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeConfidence` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

### node / purge (1 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b37f432ffcc36ce3.automaticDestinations-ms` [leftover]

### vcredist / purge (8 missed)

- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118195335.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118195335_000_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118195335_001_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118195426.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118195426_000_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118195426_001_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DELB48C.tmp` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{D7CA27E1-6F69-4444-8789-E4274FB4ED44}\.be\VC_redist.x64.exe` [leftover]

### powershell / purge (9 missed)

- `P:C:\Users\tester\AppData\Local\Microsoft\PowerShell` [leftover]
- `P:C:\WINDOWS\Prefetch\PWSH.EXE-28EDFA52.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\PowerShellCore` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Analytic` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Debug` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Operational` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{f90714a8-5509-434a-bf6d-b1624c8a19a2}` [leftover] (partial)
- `K:HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f90714a8-5509-434a-bf6d-b1624c8a19a2}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{N49227RN-5NS0-Q494-N3S1-0918N278RQ71}` [leftover]

