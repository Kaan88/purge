# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 6 | 174 | 8.4% | 8.4% | 5.6% | 8.4% | 8.4% | 5.6% | 100.0% | 1 | 0 | 4 | 4 | 0 | 0 | 0 | 15 | 13 | 0.0% | 25.0% | 16.5% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 1 | 3 | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python | purge | 7 | 42 | 2.4% | 2.4% | 0.0% | 2.4% | 2.4% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 4 | 1 | 1 | 0 | 0 | 5 | 0 |
| python312-with-313 | purge | 7 | 55 | 1.8% | 1.8% | 0.0% | 1.8% | 1.8% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 4 | 1 | 1 | 0 | 0 | 5 | 0 |
| python313-with-312 | purge | 7 | 50 | 2.0% | 2.0% | 0.0% | 2.0% | 2.0% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 5 | 1 | 1 | 0 | 0 | 5 | 0 |
| vcredist | purge | 2 | 9 | 11.1% | 11.1% | 0.0% | 11.1% | 11.1% | 0.0% | - | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |
| powershell | purge | 2 | 15 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| temurin | purge | 0 | 0 | - | - | - | - | - | - | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| 7zip | purge | 0/2 0.0% | 1/1 100.0% | 0/0 - | 0/0 - |
| python | purge | 0/25 0.0% | 0/2 0.0% | 1/9 11.1% | 0/6 0.0% |
| python312-with-313 | purge | 0/25 0.0% | 0/6 0.0% | 1/11 9.1% | 0/13 0.0% |
| python313-with-312 | purge | 0/24 0.0% | 0/0 - | 1/8 12.5% | 0/18 0.0% |
| vcredist | purge | 0/7 0.0% | 0/0 - | 1/2 50.0% | 0/0 - |
| powershell | purge | 0/2 0.0% | 0/7 0.0% | 0/1 0.0% | 0/5 0.0% |
| temurin | purge | 0/0 - | 0/0 - | 0/0 - | 0/0 - |

## Truth labels and ambient removal

- **7zip**: ambient=127, kept_owner=0, leftover=3, rig=0, user_data=0; ambient: m1bd-null1 removed 95, m1bd-null2 removed 99, m1bd-null3 removed 96
- **python**: ambient=402, leftover=41, rig=1, user_data=1; ambient: m1bd-null1 removed 360, m1bd-null2 removed 317, m1bd-null3 removed 153
- **python312-with-313**: ambient=309, kept_owner=42, leftover=54, rig=1, user_data=1; ambient: m1bd-null1 removed 260, m1bd-null2 removed 231, m1bd-null3 removed 67
- **python313-with-312**: ambient=318, kept_owner=44, leftover=49, rig=1, user_data=1; ambient: m1bd-null1 removed 285, m1bd-null2 removed 245, m1bd-null3 removed 82
- **vcredist**: ambient=350, leftover=9, rig=1; ambient: m1bd-null1 removed 334, m1bd-null2 removed 286, m1bd-null3 removed 122
- **powershell**: ambient=483, kept_owner=2, leftover=15, rig=1; ambient: m1bd-null1 removed 340, m1bd-null2 removed 332, m1bd-null3 removed 164
- **temurin**: ambient=348, rig=1; ambient: m1bd-null1 removed 326, m1bd-null2 removed 283, m1bd-null3 removed 138

## Danger items

- python / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- python312-with-313 / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- python313-with-312 / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Package Cache\{9b3415f5-afcc-46ea-9954-a8000df10f86}\python-3.13.17-amd64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vcredist / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\ProgramData\Package Cache\{d8bbe9f9-7c5b-42c6-b715-9ee898a2e515}\VC_redist.x64.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- python / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Python
- python / purge: `K:HKLM\SOFTWARE\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 80 entries left inside (60 existed in snap0), e.g. K:HKLM\SOFTWARE\Python\PythonCore, K:HKLM\SOFTWARE\Python\PythonCore\3.11, V:HKLM\SOFTWARE\Python\PythonCore\3.11|DisplayName; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\Python
- python / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\IDLE (Python 3.11 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\Python 3.11 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\Python 3.11 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11
- python / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` (Blocked) - not empty after the plan's other removals: 4 entries left inside (0 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\IDLE (Python 3.12 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 Manuals (64-bit).lnk
- python / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\IDLE (Python 3.13 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13
- python312-with-313 / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Python; as a plain delete: covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- python312-with-313 / purge: `K:HKLM\SOFTWARE\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 80 entries left inside (60 existed in snap0), e.g. K:HKLM\SOFTWARE\Python\PythonCore, K:HKLM\SOFTWARE\Python\PythonCore\3.11, V:HKLM\SOFTWARE\Python\PythonCore\3.11|DisplayName; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\Python
- python312-with-313 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\IDLE (Python 3.11 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\Python 3.11 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\Python 3.11 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11
- python312-with-313 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` (Blocked) - not empty after the plan's other removals: 4 entries left inside (0 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\IDLE (Python 3.12 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 Manuals (64-bit).lnk
- python312-with-313 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\IDLE (Python 3.13 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13
- python313-with-312 / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Python; as a plain delete: covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- python313-with-312 / purge: `K:HKLM\SOFTWARE\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 80 entries left inside (80 existed in snap0), e.g. K:HKLM\SOFTWARE\Python\PythonCore, K:HKLM\SOFTWARE\Python\PythonCore\3.11, V:HKLM\SOFTWARE\Python\PythonCore\3.11|DisplayName; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\Python
- python313-with-312 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\IDLE (Python 3.11 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\Python 3.11 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11\Python 3.11 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.11
- python313-with-312 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\IDLE (Python 3.12 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\Python 3.12 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12
- python313-with-312 / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (4 existed in snap0), e.g. P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\IDLE (Python 3.13 64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 (64-bit).lnk, P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13\Python 3.13 Manuals (64-bit).lnk; as a plain delete: existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.13

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| python | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python312-with-313 | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python313-with-312 | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
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
| python | purge | 0 | 0 | - |
| python312-with-313 | purge | 42 | 42 | 100.0% |
| python313-with-312 | purge | 44 | 44 | 100.0% |
| vcredist | purge | 0 | 0 | - |
| powershell | purge | 2 | 2 | 100.0% |
| temurin | purge | 0 | 0 | - |

## Missed truth items (first 50 per app and tool; full list in the JSON)

### 7zip / purge (2 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]

### python / purge (41 missed)

- `P:C:\Program Files\Python312` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` [leftover]
- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL87DB.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_006_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203401_007_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118203728_007_core_AllUsers.log` [leftover]
- `P:C:\WINDOWS\Installer\{984178D8-5728-48E7-89A1-C3E9A4D5F5DE}` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12` [leftover]
- `K:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python312\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python312\Doc\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{984178D8-5728-48E7-89A1-C3E9A4D5F5DE}\` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{8F3DB878-588A-4B76-BAE0-85E633A65BC2}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|16` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|17` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment|Path` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeConfidence` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

### python312-with-313 / purge (54 missed)

- `P:C:\Program Files\Python312` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12` [leftover]
- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DELEAF5.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_006_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204556_007_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261118204916_007_core_AllUsers.log` [leftover]
- `P:C:\WINDOWS\Installer\{984178D8-5728-48E7-89A1-C3E9A4D5F5DE}` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\ServiceInstances\a926c0d7-7abc-4140-a9f8-5486703f3744` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\Help` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\Idle` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\IdleShortcuts` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\InstalledFeatures` [leftover]
- `K:HKLM\SOFTWARE\Python\PythonCore\3.12\PythonPath` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python312\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\Program Files\Python312\Doc\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Python 3.12\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{984178D8-5728-48E7-89A1-C3E9A4D5F5DE}\` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\MACHINE\DRIVERS` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{2F26360E-252D-4DB5-B435-C6B72C089B16}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|18` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|19` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|20` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance|SD` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Windows Defender\Windows Defender Cleanup|SD` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows Security Health|LastHeartbeat` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\PolicyApplicationState|PolicyState` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment|Path` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

### python313-with-312 / purge (49 missed)

- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL4D5C.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DEL7B43.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.1 (64-bit)_20261118205822.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118205654_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.13.17 (64-bit)_20261118210117_007_core_AllUsers.log` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-95C4C392.pf` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{558C4CF1-82E8-4C42-BC91-5F1E96E9C99C}\` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders|C:\WINDOWS\Installer\{8078A005-EBA5-4E1A-9AAF-EC4693A1D7C3}\` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{E3BC303B-6343-48D1-980B-89C1FAB698E3}\.be\python-3.13.17-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{05SS6476-SOS9-40N2-24Q2-168978RS936Q}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|18` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|19` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|20` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AvTracking\History|TimeStamp` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\AppInv|LastRunTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\AvStatus|LastRunTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\DevInv|LastRunTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController\GenTel|LastRunTime` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|dev` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|doc` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|doc_shortcut` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|exe` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|lib` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|path` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|pip` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|Shortcuts` [leftover]
- `C:HKLM\SOFTWARE\Python\PythonCore\3.13\InstalledFeatures|tcltk` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

### vcredist / purge (8 missed)

- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118211333.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118211333_000_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118211333_001_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118211528.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118211528_000_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261118211528_001_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DEL391.tmp` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{6AE76328-8FB0-45C7-95C9-7D5B3961CFE7}\.be\VC_redist.x64.exe` [leftover]

### powershell / purge (15 missed)

- `P:C:\Users\tester\AppData\Local\Microsoft\PowerShell` [leftover]
- `P:C:\WINDOWS\Prefetch\PWSH.EXE-28EDFA52.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\PowerShellCore` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\88E286864E97CDA59B99F3358049C677` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Analytic` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Debug` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore/Operational` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{f90714a8-5509-434a-bf6d-b1624c8a19a2}` [leftover] (partial)
- `K:HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f90714a8-5509-434a-bf6d-b1624c8a19a2}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{N49227RN-5NS0-Q494-N3S1-0918N278RQ71}` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeEstimated` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeHigh` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits|SecureTimeLow` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeConfidence` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\W32Time\SecureTimeLimits\RunTime|SecureTimeTickCount` [leftover]

