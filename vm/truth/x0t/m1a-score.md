# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 1 | 47 | 51.1% | 51.1% | 0.0% | 51.1% | 51.1% | 0.0% | - | 0 | 3 | 0 | 0 | 0 | 0 | 46.2% | 69.6% | 66.7% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npp-userfiles | purge | 6 | 47 | 51.1% | 51.1% | 0.0% | 51.1% | 51.1% | 0.0% | - | 0 | 3 | 0 | 0 | 0 | 3 | 3 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| npp-userfiles | purge | 6/13 46.2% | 16/23 69.6% | 2/3 66.7% | 0/8 0.0% |

## Truth labels and ambient removal

- **npp-userfiles**: ambient=400, kept_owner=0, leftover=44, rig=1, user_data=3; ambient: r0-null1 removed 152, r0-null2 removed 159, r0-null3 removed 152

## Danger items

- npp-userfiles / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a
- npp-userfiles / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a` (Likely) - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a
- npp-userfiles / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| npp-userfiles | purge | 0 | 0 | 3 | 1 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

- npp-userfiles / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a
- npp-userfiles / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a` (Likely, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a
- npp-userfiles / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe

### (2) unticked user data

- npp-userfiles / purge: `P:C:\Users\tester\AppData\Roaming\Notepad++` (Likely, Quarantine) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### npp-userfiles / purge (23 missed)

- `P:C:\Program Files\Notepad++\my-notes` [user_data]
- `P:C:\Program Files\Notepad++\session-backup.txt` [user_data]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\1d875bbc-99d9-4f49-b465-a8a397512bf7_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem73BA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1436` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2928` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3456` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6376` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6856` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7452` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

