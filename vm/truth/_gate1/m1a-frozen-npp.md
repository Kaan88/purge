# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 1 | 29 | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 100.0% | 0 | 0 | 0 | 0 | 0.0% | 6.2% | 0.0% | - |
| purge | 1 | 29 | 79.3% | 75.9% | 0.0% | 79.3% | 75.9% | 0.0% | - | 0 | 0 | 0 | 0 | 50.0% | 100.0% | 66.7% | - |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | hit | danger | ambient | gone | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npp | purge | 2 | 29 | 79.3% | 75.9% | 0.0% | 79.3% | 75.9% | 0.0% | - | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| npp | bcu | 10 | 29 | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 3.4% | 100.0% | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 9 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| npp | purge | 5/10 50.0% | 16/16 100.0% | 2/3 66.7% | 0/0 - |
| npp | bcu | 0/10 0.0% | 1/16 6.2% | 0/3 0.0% | 0/0 - |

## Truth labels and ambient removal

- **npp**: ambient=167, kept_owner=0, leftover=29, rig=0, user_data=0; ambient: null1 removed 78, null2 removed 72, null3 removed 70

## Danger items

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### npp / purge (6 missed)

- `P:C:\ProgramData\Microsoft\Windows\AppRepository\fb764295-5706-4eaf-8f28-603f30273874_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem5A6A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]

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

