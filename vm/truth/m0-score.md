# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 8 | 269 | 7.2% | 7.2% | 7.2% | 7.2% | 7.2% | 7.2% | 75.0% | 4 | 1 | 1 | 1 | 0.0% | 31.2% | 0.0% | - |
| clone | 8 | 269 | 0.4% | 0.4% | 0.4% | 0.4% | 0.4% | 0.4% | 25.0% | 0 | 2 | 2 | 0 | 0.0% | 1.2% | 0.0% | - |
| ut | 5 | 253 | 2.5% | 2.5% | 2.5% | 2.5% | 2.5% | 2.5% | 80.0% | 1 | 1 | 1 | 1 | 5.7% | 2.5% | 0.0% | - |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | hit | danger | ambient | gone | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npp | bcu | 10 | 29 | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 100.0% | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 9 | 0 |
| npp | clone | 2 | 29 | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 50.0% | 0 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 0 |
| npp | ut | 9 | 29 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 9 | 0 |
| 7zip | bcu | 20 | 3 | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 100.0% | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 19 | 0 |
| 7zip | clone | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vscode | bcu | 202 | 154 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 202 | 0 |
| vscode | clone | 0 | 154 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vscode | ut | 202 | 154 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 202 | 0 |
| git | bcu | 14 | 16 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| git | clone | 0 | 16 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| git | ut | 14 | 16 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| python | bcu | 65 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 64 | 0 |
| python | clone | 1 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| python | ut | 64 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 64 | 0 |
| node | bcu | 10 | 4 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 10 | 0 |
| node | clone | 0 | 4 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vcredist | bcu | 23 | 9 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 23 | 0 |
| vcredist | clone | 0 | 9 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| firefox | bcu | 17 | 24 | 20.8% | 20.8% | 20.8% | 20.8% | 20.8% | 20.8% | 100.0% | 4 | 0 | 0 | 1 | 9 | 0 | 0 | 8 | 0 |
| firefox | clone | 0 | 24 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| firefox | ut | 37 | 24 | 12.5% | 12.5% | 12.5% | 12.5% | 12.5% | 12.5% | 80.0% | 1 | 1 | 1 | 1 | 4 | 1 | 0 | 32 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| npp | bcu | 0/10 0.0% | 1/16 6.2% | 0/3 0.0% | 0/0 - |
| npp | clone | 0/10 0.0% | 1/16 6.2% | 0/3 0.0% | 0/0 - |
| npp | ut | 0/10 0.0% | 0/16 0.0% | 0/3 0.0% | 0/0 - |
| 7zip | bcu | 0/2 0.0% | 1/1 100.0% | 0/0 - | 0/0 - |
| 7zip | clone | 0/2 0.0% | 0/1 0.0% | 0/0 - | 0/0 - |
| vscode | bcu | 0/13 0.0% | 0/139 0.0% | 0/2 0.0% | 0/0 - |
| vscode | clone | 0/13 0.0% | 0/139 0.0% | 0/2 0.0% | 0/0 - |
| vscode | ut | 0/13 0.0% | 0/139 0.0% | 0/2 0.0% | 0/0 - |
| git | bcu | 0/8 0.0% | 0/2 0.0% | 0/6 0.0% | 0/0 - |
| git | clone | 0/8 0.0% | 0/2 0.0% | 0/6 0.0% | 0/0 - |
| git | ut | 0/8 0.0% | 0/2 0.0% | 0/6 0.0% | 0/0 - |
| python | bcu | 0/25 0.0% | 0/0 - | 0/5 0.0% | 0/0 - |
| python | clone | 0/25 0.0% | 0/0 - | 0/5 0.0% | 0/0 - |
| python | ut | 0/25 0.0% | 0/0 - | 0/5 0.0% | 0/0 - |
| node | bcu | 0/1 0.0% | 0/0 - | 0/3 0.0% | 0/0 - |
| node | clone | 0/1 0.0% | 0/0 - | 0/3 0.0% | 0/0 - |
| vcredist | bcu | 0/7 0.0% | 0/0 - | 0/2 0.0% | 0/0 - |
| vcredist | clone | 0/7 0.0% | 0/0 - | 0/2 0.0% | 0/0 - |
| firefox | bcu | 0/7 0.0% | 5/10 50.0% | 0/7 0.0% | 0/0 - |
| firefox | clone | 0/7 0.0% | 0/10 0.0% | 0/7 0.0% | 0/0 - |
| firefox | ut | 2/7 28.6% | 1/10 10.0% | 0/7 0.0% | 0/0 - |

## Truth labels and ambient removal

- **npp**: ambient=167, kept_owner=0, leftover=29, rig=0, user_data=0; ambient: null1 removed 78, null2 removed 72, null3 removed 70
- **7zip**: ambient=89, kept_owner=0, leftover=3, rig=0, user_data=0; ambient: null1 removed 68, null2 removed 66, null3 removed 66
- **vscode**: ambient=171, kept_owner=0, leftover=152, rig=0, user_data=2; ambient: null1 removed 74, null2 removed 76, null3 removed 70
- **git**: ambient=123, kept_owner=0, leftover=16, rig=0, user_data=0; ambient: null1 removed 96, null2 removed 79, null3 removed 75
- **python**: ambient=113, kept_owner=29, leftover=29, rig=0, user_data=1; ambient: null1 removed 75, null2 removed 73, null3 removed 75
- **node**: ambient=94, kept_owner=0, leftover=4, rig=0, user_data=0; ambient: null1 removed 60, null2 removed 63, null3 removed 60
- **vcredist**: ambient=44, kept_owner=0, leftover=9, rig=0, user_data=0; ambient: null1 removed 25, null2 removed 26, null3 removed 26
- **firefox**: ambient=103, kept_owner=0, leftover=23, rig=0, user_data=1; ambient: null1 removed 72, null2 removed 73, null3 removed 71

## Danger items

- npp / clone: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk` (Safe, preselected) - existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk; deny: L1: Windows' own Notepad shortcut; a Notepad++ name match must never offer it (the clone pre-ticked it).
- python / bcu: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Safe, preselected) - covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- python / clone: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Safe, preselected) - covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python
- firefox / ut: `K:HKLM\SOFTWARE\Microsoft\Wbem\Tracing\Providers\ScheduledTaskProv @ Root/Microsoft/Windows/TaskScheduler` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Microsoft\Wbem\Tracing\Providers\ScheduledTaskProv @ Root/Microsoft/Windows/TaskScheduler

## Missed truth items (first 50 per app and tool; full list in the JSON)

### npp / bcu (28 missed)

- `P:C:\Program Files\WindowsApps\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\fb764295-5706-4eaf-8f28-603f30273874_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem5A6A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{E6950302-61F0-4FEB-97DB-855E30D4A991}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StagingInfo\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\PackageState\S-1-5-21-1336749127-99101324-1432799918-1000\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NotepadPlusPlus_2247w0b46hfww!NotepadPlusPlus` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\S-1-15-2-2557016000-3416274266-3014759505-2624777461-3676268001-1533065058-806985695` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\notepadplusplus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-In-Block` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-Out-Block` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

### npp / clone (28 missed)

- `P:C:\Program Files\WindowsApps\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\fb764295-5706-4eaf-8f28-603f30273874_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem5A6A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{E6950302-61F0-4FEB-97DB-855E30D4A991}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StagingInfo\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\PackageState\S-1-5-21-1336749127-99101324-1432799918-1000\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NotepadPlusPlus_2247w0b46hfww!NotepadPlusPlus` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\S-1-15-2-2557016000-3416274266-3014759505-2624777461-3676268001-1533065058-806985695` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\notepadplusplus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-In-Block` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-Out-Block` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

### npp / ut (29 missed)

- `P:C:\Program Files\WindowsApps\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\fb764295-5706-4eaf-8f28-603f30273874_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `P:C:\ProgramData\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem5A6A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{E6950302-61F0-4FEB-97DB-855E30D4A991}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StagingInfo\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\PackageState\S-1-5-21-1336749127-99101324-1432799918-1000\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Notepad++` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NotepadPlusPlus_2247w0b46hfww!NotepadPlusPlus` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\S-1-15-2-2557016000-3416274266-3014759505-2624777461-3676268001-1533065058-806985695` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\notepadplusplus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\NotepadPlusPlus_2247w0b46hfww` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\PackagedCom\Package\NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-In-Block` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules|NotepadPlusPlus_2247w0b46hfww-Out-Block` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

### 7zip / bcu (2 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]

### 7zip / clone (3 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\7-Zip` [leftover]

### vscode / bcu (154 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794413062.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ascx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.asp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.aspx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_login` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_logout` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_profile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bashrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bib` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bowerrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c++` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cc\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cfg` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cjs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clj` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clojure` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cls\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cmake` [leftover]
- `K:HKLM\SOFTWARE\Classes\.code-workspace` [leftover]
- `K:HKLM\SOFTWARE\Classes\.coffee` [leftover]
- `K:HKLM\SOFTWARE\Classes\.config` [leftover]
- `K:HKLM\SOFTWARE\Classes\.containerfile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cpp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cs\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cshtml` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csproj\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.css\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csv\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ctp` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cxx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dart` [leftover]
- `K:HKLM\SOFTWARE\Classes\.diff` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dockerfile` [leftover]

### vscode / clone (154 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794413062.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ascx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.asp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.aspx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_login` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_logout` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_profile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bashrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bib` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bowerrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c++` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cc\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cfg` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cjs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clj` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clojure` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cls\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cmake` [leftover]
- `K:HKLM\SOFTWARE\Classes\.code-workspace` [leftover]
- `K:HKLM\SOFTWARE\Classes\.coffee` [leftover]
- `K:HKLM\SOFTWARE\Classes\.config` [leftover]
- `K:HKLM\SOFTWARE\Classes\.containerfile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cpp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cs\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cshtml` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csproj\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.css\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csv\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ctp` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cxx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dart` [leftover]
- `K:HKLM\SOFTWARE\Classes\.diff` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dockerfile` [leftover]

### vscode / ut (154 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794413062.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ascx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.asp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.aspx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_login` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_logout` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_profile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bashrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bib` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bowerrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c++` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cc\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cfg` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cjs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clj` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cljx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clojure` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cls\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cmake` [leftover]
- `K:HKLM\SOFTWARE\Classes\.code-workspace` [leftover]
- `K:HKLM\SOFTWARE\Classes\.coffee` [leftover]
- `K:HKLM\SOFTWARE\Classes\.config` [leftover]
- `K:HKLM\SOFTWARE\Classes\.containerfile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cpp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cs\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cshtml` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csproj\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.css\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csv\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.csx` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ctp` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cxx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dart` [leftover]
- `K:HKLM\SOFTWARE\Classes\.diff` [leftover]
- `K:HKLM\SOFTWARE\Classes\.dockerfile` [leftover]

### git / bcu (16 missed)

- `P:C:\Users\tester\AppData\Local\Temp\is-TU8SYANY8F-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\sh_auto_file` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]

### git / clone (16 missed)

- `P:C:\Users\tester\AppData\Local\Temp\is-TU8SYANY8F-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\sh_auto_file` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]

### git / ut (16 missed)

- `P:C:\Users\tester\AppData\Local\Temp\is-TU8SYANY8F-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\LibraryFolder\background\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\sh_auto_file` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]

### python / bcu (30 missed)

- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL3917.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_007_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\97992354503a502a.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\cfa2f398f6b586de.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{02B2D1F1-8678-4210-91C4-2EBAA1D6E115}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]

### python / clone (30 missed)

- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL3917.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_007_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\97992354503a502a.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\cfa2f398f6b586de.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{02B2D1F1-8678-4210-91C4-2EBAA1D6E115}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]

### python / ut (30 missed)

- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Temp\DEL3917.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081112_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261111081247_007_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\97992354503a502a.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\cfa2f398f6b586de.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Users\tester\AppData\Local\Package Cache\{e9b7c837-5066-4f10-851a-69179f987b18}\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{02B2D1F1-8678-4210-91C4-2EBAA1D6E115}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.NhgbTrarengrq.{401RRN19-N821-9P37-NS46-1S4QSR85QQO9}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]

### node / bcu (4 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b37f432ffcc36ce3.automaticDestinations-ms` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|3` [leftover]

### node / clone (4 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b37f432ffcc36ce3.automaticDestinations-ms` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|1` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|2` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|3` [leftover]

### vcredist / bcu (9 missed)

- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081711.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081711_000_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081711_001_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081747.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081747_000_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081747_001_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DEL1DB4.tmp` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\ProgramData\Package Cache\{d8bbe9f9-7c5b-42c6-b715-9ee898a2e515}\VC_redist.x64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{E45983CB-B1FA-4CCD-B578-BBBC000A86E3}\.be\VC_redist.x64.exe` [leftover]

### vcredist / clone (9 missed)

- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081711.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081711_000_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081711_001_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081747.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081747_000_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261111081747_001_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DEL1DB4.tmp` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\ProgramData\Package Cache\{d8bbe9f9-7c5b-42c6-b715-9ee898a2e515}\VC_redist.x64.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{E45983CB-B1FA-4CCD-B578-BBBC000A86E3}\.be\VC_redist.x64.exe` [leftover]

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

### firefox / clone (24 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Mozilla` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Mozilla` [user_data]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\Firefox` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{AC21D679-A9C1-47A0-B96F-A0625A9EE822}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]

### firefox / ut (21 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` [leftover]
- `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` [leftover] (partial)
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{AC21D679-A9C1-47A0-B96F-A0625A9EE822}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]

