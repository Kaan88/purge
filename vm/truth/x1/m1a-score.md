# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 16 | 1593 | 27.8% | 21.3% | 15.0% | 21.6% | 20.0% | 15.0% | 92.2% | 13 | 45 | 9 | 0 | 9 | 9 | 18.4% | 24.9% | 22.7% | 2.3% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| git-toolsdir | purge | 6 | 61 | 8.2% | 8.2% | 3.3% | 8.2% | 8.2% | 3.3% | 100.0% | 0 | 1 | 0 | 0 | 0 | 5 | 1 | 0 | 0 | 0 | 0 |
| git-userstate | purge | 10 | 36 | 13.9% | 13.9% | 5.6% | 13.9% | 13.9% | 5.6% | 100.0% | 0 | 5 | 0 | 0 | 0 | 5 | 5 | 0 | 0 | 0 | 0 |
| vscode-userstate | purge | 142 | 209 | 77.5% | 77.5% | 63.6% | 64.6% | 64.6% | 63.6% | 98.5% | 0 | 5 | 2 | 0 | 0 | 137 | 5 | 0 | 0 | 0 | 0 |
| vscode-zipcopy | purge | 139 | 207 | 73.4% | 72.9% | 65.2% | 65.7% | 65.2% | 65.2% | 100.0% | 0 | 3 | 0 | 0 | 0 | 136 | 3 | 0 | 0 | 0 | 0 |
| git-upgrade | purge | 7 | 57 | 12.3% | 12.3% | 3.5% | 12.3% | 12.3% | 3.5% | 100.0% | 0 | 0 | 0 | 0 | 0 | 7 | 0 | 0 | 0 | 0 | 0 |
| npp-userfiles | purge | 6 | 57 | 42.1% | 42.1% | 0.0% | 42.1% | 42.1% | 0.0% | - | 0 | 3 | 0 | 0 | 0 | 3 | 3 | 0 | 0 | 0 | 0 |
| ff-esr | purge | 21 | 55 | 34.5% | 9.1% | 7.3% | 20.0% | 9.1% | 7.3% | 100.0% | 0 | 7 | 0 | 0 | 2 | 12 | 7 | 0 | 0 | 2 | 0 |
| ff-devedition | purge | 21 | 68 | 27.9% | 7.4% | 5.9% | 16.2% | 7.4% | 5.9% | 100.0% | 0 | 7 | 0 | 0 | 2 | 12 | 7 | 0 | 0 | 2 | 0 |
| vscode-with-user | purge | 3 | 200 | 0.5% | 0.5% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 3 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 | 0 |
| thunderbird | purge | 25 | 62 | 17.7% | 14.5% | 9.7% | 16.1% | 14.5% | 9.7% | 100.0% | 10 | 1 | 0 | 0 | 0 | 24 | 1 | 0 | 0 | 0 | 0 |
| ff-tbafter | purge | 12 | 80 | 11.2% | 7.5% | 6.2% | 11.2% | 7.5% | 6.2% | 100.0% | 1 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| vscode-insiders-pair | purge | 4 | 60 | 3.3% | 3.3% | 0.0% | 3.3% | 3.3% | 0.0% | 100.0% | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| vscode-upgrade | purge | 140 | 200 | 69.0% | 69.0% | 68.0% | 69.0% | 69.0% | 68.0% | 100.0% | 0 | 0 | 0 | 0 | 0 | 140 | 0 | 0 | 0 | 0 | 0 |
| ff-reinstall | purge | 15 | 24 | 50.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 10 | 7 | 0 | 5 | 0 | 10 | 0 | 0 | 5 | 0 |
| vlc | purge | 6 | 100 | 3.0% | 3.0% | 1.0% | 3.0% | 3.0% | 1.0% | 100.0% | 2 | 0 | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 0 |
| winmerge | purge | 0 | 117 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| git-toolsdir | purge | 0/22 0.0% | 2/18 11.1% | 3/20 15.0% | 0/1 0.0% |
| git-userstate | purge | 0/12 0.0% | 2/13 15.4% | 3/8 37.5% | 0/3 0.0% |
| vscode-userstate | purge | 28/46 60.9% | 134/157 85.4% | 0/3 0.0% | 0/3 0.0% |
| vscode-zipcopy | purge | 15/47 31.9% | 136/151 90.1% | 0/4 0.0% | 1/5 20.0% |
| git-upgrade | purge | 0/15 0.0% | 2/24 8.3% | 5/15 33.3% | 0/3 0.0% |
| npp-userfiles | purge | 6/15 40.0% | 16/33 48.5% | 2/6 33.3% | 0/3 0.0% |
| ff-esr | purge | 8/29 27.6% | 1/8 12.5% | 10/13 76.9% | 0/5 0.0% |
| ff-devedition | purge | 8/32 25.0% | 1/14 7.1% | 10/17 58.8% | 0/5 0.0% |
| vscode-with-user | purge | 0/44 0.0% | 0/149 0.0% | 0/1 0.0% | 1/6 16.7% |
| thunderbird | purge | 3/25 12.0% | 5/28 17.9% | 3/4 75.0% | 0/5 0.0% |
| ff-tbafter | purge | 2/28 7.1% | 3/34 8.8% | 4/14 28.6% | 0/4 0.0% |
| vscode-insiders-pair | purge | 1/37 2.7% | 1/12 8.3% | 0/6 0.0% | 0/5 0.0% |
| vscode-upgrade | purge | 1/35 2.9% | 137/160 85.6% | 0/3 0.0% | 0/2 0.0% |
| ff-reinstall | purge | 12/15 80.0% | 0/2 0.0% | 0/1 0.0% | 0/6 0.0% |
| vlc | purge | 1/28 3.6% | 0/24 0.0% | 2/45 4.4% | 0/3 0.0% |
| winmerge | purge | 0/12 0.0% | 0/91 0.0% | 0/9 0.0% | 0/5 0.0% |

## Truth labels and ambient removal

- **git-toolsdir**: ambient=556, kept_owner=0, leftover=61, rig=1, user_data=0; ambient: f0-null1 removed 290, f0-null2 removed 280, f0-null3 removed 490
- **git-userstate**: ambient=215, kept_owner=0, leftover=36, rig=2, user_data=0; ambient: f0-null1 removed 158, f0-null2 removed 88, f0-null3 removed 151
- **vscode-userstate**: ambient=456, kept_owner=0, leftover=180, rig=1, user_data=29; ambient: f0-null1 removed 300, f0-null2 removed 227, f0-null3 removed 289
- **vscode-zipcopy**: ambient=664, kept_owner=0, leftover=192, rig=1, user_data=15; ambient: f0-null1 removed 329, f0-null2 removed 257, f0-null3 removed 508
- **git-upgrade**: ambient=338, kept_owner=0, leftover=57, rig=1, user_data=0; ambient: f0-null1 removed 281, f0-null2 removed 223, f0-null3 removed 293
- **npp-userfiles**: ambient=383, kept_owner=0, leftover=54, rig=1, user_data=3; ambient: f0-null1 removed 293, f0-null2 removed 235, f0-null3 removed 295
- **ff-esr**: ambient=382, kept_owner=3, leftover=49, rig=2, user_data=6; ambient: f0-null1 removed 102, f0-null2 removed 85, f0-null3 removed 326
- **ff-devedition**: ambient=376, kept_owner=3, leftover=62, rig=2, user_data=6; ambient: f0-null1 removed 257, f0-null2 removed 240, f0-null3 removed 317
- **vscode-with-user**: ambient=630, kept_owner=0, leftover=185, rig=2, user_data=15; ambient: f0-null1 removed 266, f0-null2 removed 249, f0-null3 removed 491
- **thunderbird**: ambient=354, kept_owner=0, leftover=61, rig=1, user_data=1; ambient: f0-null1 removed 318, f0-null2 removed 243, f0-null3 removed 305
- **ff-tbafter**: ambient=510, kept_owner=31, leftover=79, rig=1, user_data=1; ambient: f0-null1 removed 376, f0-null2 removed 302, f0-null3 removed 434
- **vscode-insiders-pair**: ambient=631, kept_owner=0, leftover=58, rig=2, user_data=2; ambient: f0-null1 removed 248, f0-null2 removed 231, f0-null3 removed 472
- **vscode-upgrade**: ambient=740, kept_owner=0, leftover=198, rig=1, user_data=2; ambient: f0-null1 removed 335, f0-null2 removed 278, f0-null3 removed 586
- **ff-reinstall**: ambient=96, kept_owner=0, leftover=16, rig=2, user_data=8; ambient: f0-null1 removed 60, f0-null2 removed 43, f0-null3 removed 51
- **vlc**: ambient=428, kept_owner=0, leftover=100, rig=1, user_data=0; ambient: f0-null1 removed 341, f0-null2 removed 270, f0-null3 removed 392
- **winmerge**: ambient=367, kept_owner=0, leftover=117, rig=1, user_data=0; ambient: f0-null1 removed 319, f0-null2 removed 248, f0-null3 removed 300

## Danger items

- git-toolsdir / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH
- git-userstate / purge: `S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd` (Likely) - existed in snap0: S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd
- vscode-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe\shell\open\command|` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe\shell\open\command|
- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.edn` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Classes\.edn
- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.gemspec` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Classes\.gemspec
- vscode-userstate / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|
- vscode-zipcopy / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode
- vscode-zipcopy / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- npp-userfiles / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a
- npp-userfiles / purge: `S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a` (Likely) - existed in snap0: S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a
- npp-userfiles / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\notepad++.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\notepad++.exe
- ff-esr / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-esr / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-esr / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- ff-devedition / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-devedition / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-devedition / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-devedition / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-devedition / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\updater.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\updater.exe
- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- vscode-with-user / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Blocked) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode
- thunderbird / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1871224937-2691627691-3762806239-1000|\Device\HarddiskVolume4\Program Files\Mozilla Thunderbird\thunderbird.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- ff-reinstall / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID
- ff-reinstall / purge: `K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox
- ff-reinstall / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` (Likely) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\MaintenanceService
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB` (Safe, preselected) - existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 246 entries left inside (119 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\8m59q2e6.default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 274 entries left inside (147 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\f1ic8jbo.MozillaBackgroundTask-308046B0AF4A39CB-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 268 entries left inside (169 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\ez2i8quj.default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 278 entries left inside (151 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\2eww8c4o.MozillaBackgroundTask-308046B0AF4A39CB-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-reinstall / purge: `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 3 entries left inside (3 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox, K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox\TaskBarIDs, V:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox\TaskBarIDs|C:\Program Files\Mozilla Firefox; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Mozilla
- ff-reinstall / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 10 entries left inside (10 existed in snap0), e.g. K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox, V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox|Uninstalled-release, K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox\DllPrefetchExperiment; as a plain delete: existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 139 entries left inside (125 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\el1xvb8j.default-release; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 150 entries left inside (142 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\rds9x0m6.MozillaBackgroundTask-308046B0AF4A39CB-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-reinstall / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 2 entries left inside (2 existed in snap0), e.g. P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB, P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB\parent.lock; as a plain delete: existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| git-toolsdir | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| git-userstate | purge | 0 | 0 | 0 | 0 | 5 | 0 | 0 |
| vscode-userstate | purge | 0 | 0 | 2 | 2 | 1 | 2 | 0 |
| vscode-zipcopy | purge | 0 | 0 | 3 | 1 | 0 | 0 | 0 |
| git-upgrade | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| npp-userfiles | purge | 0 | 0 | 3 | 1 | 0 | 0 | 0 |
| ff-esr | purge | 0 | 0 | 7 | 1 | 0 | 0 | 0 |
| ff-devedition | purge | 0 | 0 | 7 | 1 | 0 | 0 | 0 |
| vscode-with-user | purge | 0 | 0 | 3 | 0 | 0 | 0 | 0 |
| thunderbird | purge | 0 | 0 | 1 | 1 | 0 | 0 | 0 |
| ff-tbafter | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| vscode-insiders-pair | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| vscode-upgrade | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| ff-reinstall | purge | 7 | 0 | 3 | 1 | 0 | 0 | 0 |
| vlc | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| winmerge | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

- ff-reinstall / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID
- ff-reinstall / purge: `K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox
- ff-reinstall / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB` (Safe, preselected, Quarantine) danger - existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB

### (1) blocking user data

None.

### (2) unticked danger

- git-toolsdir / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe
- vscode-userstate / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|
- vscode-zipcopy / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode
- vscode-zipcopy / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- npp-userfiles / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a
- npp-userfiles / purge: `S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a` (Likely, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a
- npp-userfiles / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\notepad++.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\notepad++.exe
- ff-esr / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-esr / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-esr / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Mozilla Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- ff-devedition / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-devedition / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-devedition / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox
- ff-devedition / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-devedition / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\updater.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\updater.exe
- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- vscode-with-user / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Blocked, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode
- thunderbird / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1871224937-2691627691-3762806239-1000|\Device\HarddiskVolume4\Program Files\Mozilla Thunderbird\thunderbird.exe` (Blocked, DeleteValue) danger - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` (Likely, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\MaintenanceService
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (2) unticked user data

- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- vscode-userstate / purge: `P:C:\Program Files\Microsoft VS Code` (Likely, Quarantine) hit - 
- vscode-zipcopy / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- npp-userfiles / purge: `P:C:\Users\tester\AppData\Roaming\Notepad++` (Likely, Quarantine) hit - 
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- thunderbird / purge: `P:C:\Users\tester\AppData\Roaming\Thunderbird` (Likely, Quarantine) hit - 
- ff-tbafter / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- vscode-insiders-pair / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 
- vscode-upgrade / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (3) preexisting_value_ref

- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH
- git-userstate / purge: `S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd` (Likely, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd
- vscode-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe\shell\open\command|` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe\shell\open\command|

### (3) old_empty_ext_key

- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.edn` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\.edn
- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.gemspec` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\.gemspec

## Missed truth items (first 50 per app and tool; full list in the JSON)

### git-toolsdir / purge (56 missed)

- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1720.5436.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1720.9280.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1720.1236.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1720.1236.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1720.1236.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1720.1236.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_172051_1236-6064.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_172043_5436-6048.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_172043_9280-8160.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\LightRainV3[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-LRD7T2RP6P-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct1106.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct2AC5.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct5F7.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct5F8.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\dad0483fccec544.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-34012AF4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-48D35E1C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-BEA120E0.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-93971337.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\10040` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1516` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2380` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5116` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5696` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\592` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6724` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6732` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6744` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6824` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7244` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9016` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~C:` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~https://gitforwindows.org/faq` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{7544EFB5-B932-07E6-298E-72885A921128}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{BC58A472-B80D-B8F4-07CF-28B3BBC9EB2B}` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|Data` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|ETag` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|Expires` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|LastModified` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|PotentialFailover` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Siloa0620cf7-723c-0f27-95db-a70eda2d151ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Siloa0620cf7-723c-0f27-95db-a70eda2d151csoftware` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Siloefe0fcfc-37e7-2958-8dd1-9a10f1b5477fcom` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{97E467B4-98C6-4F19-9588-161B7773D6F6} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]

### git-userstate / purge (31 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-KBDVXEPQ20-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-AC6D43A4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1888` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1980` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5244` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6848` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9352` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.diff` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.patch` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~https://gitforwindows.org/faq` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Git` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Usage|LANConnectionCount` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]

### vscode-userstate / purge (47 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\LightRainV3[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794591127.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\10108` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\10224` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1620` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1952` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3520` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3652` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4972` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\500` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5128` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6704` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6712` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6728` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9024` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9296` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9628` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9848` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Tuning` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WMSS` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `C:HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\52-54-00-12-35-00|WpadDecisionTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]

### vscode-zipcopy / purge (55 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794591747505-4048.log` [leftover]
- `P:C:\Users\tester\.vscode-shared\sharedStorage\state.vscdb.backup` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1742.1532.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1742.3856.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1743.5416.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1743.5416.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1743.5416.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1743.5416.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_174337_5416-1384.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_174257_1532-6256.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_174257_3856-10228.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794591717.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794591744.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct5245.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6A6E.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctCAA4.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctCAA5.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846018.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4524` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\496` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5948` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6656` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7684` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\800` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8188` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8248` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8292` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8920` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9716` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9728` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]

### git-upgrade / purge (50 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-WH79UCD6WR-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-8165BDB0.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-AC6D43A4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\10144` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1452` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1496` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3264` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3352` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4840` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5208` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6256` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6296` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7856` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7916` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8464` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8644` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gitattributes` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gitignore` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gitmodules` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~https://gitforwindows.org/faq` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Git` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|Data` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|ETag` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|Expires` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|LastModified` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\SIH\SLS\{E7A50285-D08D-499D-9FF8-180FDC2332BC}\/SLS/{E7A50285-D08D-499D-9FF8-180FDC2332BC}/x64/10.0.26340.9882/0?CH=587&L=en-US&P=&PT=0x30&WUA=1511.2610.21012.0&MK=innotek+GmbH&MD=VirtualBox|PotentialFailover` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\52-54-00-12-35-00|WpadDecisionTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]

### npp-userfiles / purge (33 missed)

- `P:C:\Program Files\Notepad++\my-notes` [user_data]
- `P:C:\Program Files\Notepad++\session-backup.txt` [user_data]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\2d446d2d-292d-42f7-a4f7-e2dd7ee2642e_S-1-5-21-1871224937-2691627691-3762806239-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\LightRainV3[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem9F10.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\10228` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2212` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2228` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2784` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2860` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4592` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4680` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5408` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6384` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6460` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7192` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7196` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7556` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8584` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9296` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9464` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Notepad++` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\52-54-00-12-35-00|WpadDecisionTime` [leftover]
- `C:HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Usage|LANConnectionCount` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### ff-esr / purge (36 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\Firefox_S-1-5-21-1871224937-2691627691-3762806239-1000_shortcuts.ini` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1807.3820.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1807.7516.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1807.5568.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1807.5568.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1807.5568.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1807.5568.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_180718_5568-4664.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_180711_3820-2976.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_180711_7516-4872.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6E47.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6E48.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct752E.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct8CFA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1856` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5132` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8080` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8612` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### ff-devedition / purge (49 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1816.4024.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1816.4648.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1816.8160.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1816.8160.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1816.8160.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1816.8160.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-13.1813.4224.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-13.1819.4224.3.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_181615_8160-9048.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_181607_4024-888.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_181607_4648-8648.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_10_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct3AA9.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct3AAA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct4384.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct5C0B.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4924` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5864` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6236` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6788` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7012` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7280` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8208` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8652` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8656` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9020` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-CA9422711AE1A81C` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
- `C:HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Usage|LANConnectionCount` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]

### vscode-with-user / purge (199 missed)

- `P:C:\Users\tester\.copilot\logs\process-1794594377877-9572.log` [leftover]
- `P:C:\Users\tester\.vscode-shared\sharedStorage\state.vscdb.backup` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1827.6360.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1827.7768.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1827.4156.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1827.4156.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1827.4156.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1827.4156.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_182718_4156-1964.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_182710_6360-2600.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_182710_7768-9244.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794594350.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct8FC9.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct8FCA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct9902.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctB1C8.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code\blob_storage\becdcd4d-464b-4837-8c97-21e98ad8ee40` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\375263d804736ac5_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\44fa04a154a74580_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\796d9a8c3efcae9c_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\b51f2acc0ca14ca2_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\d8729cfb9e1280dd_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\dd491d11bfc57885_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Code Cache\electron-preload\86E092DB02BAE6C32E3593AE143594C8D96E8501256B0FAACC09E3C70ED7BFD7-67A64C46445250C0C0E1103FCA3290FE88811449B7F10FD5FBBE5AA8F3AC1EB2.cache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Crashpad` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Local Storage\leveldb\LOG.old` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\logs\20261113T212614` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Network\TransportSecurity` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Session Storage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\globalStorage\state.vscdb.backup` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\workspaceStorage\1794594374854` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA75.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\.ascx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.asp\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.aspx\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_login` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bash_logout` [leftover]

### thunderbird / purge (51 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_13_21_39_42.etl` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\LightRainV3[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C774119C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\HELPER.EXE-1A1A68B5.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MAINTENANCESERVICE.EXE-3122AC73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MAINTENANCESERVICE_INSTALLER.-9E296A0C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PINGSENDER.EXE-CE23898A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-E1DBB6D8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNTIMEBROKER.EXE-F9ED3658.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SETUP.EXE-FFEB372C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-C5EEC15E.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\THUNDERBIRD.EXE-1770C0F6.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\THUNDERBIRD.EXE-E333F027.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UN_A.EXE-C0769F1D.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UN_B.EXE-D3CC59A2.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UNINSTALL.EXE-A78293C1.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UNINSTALLER.EXE-5AD95662.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\CLSID\{29F458BE-8866-11D5-A3DD-00B0D0F3BAA7}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\CLSID\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\Interface\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\MozillaMapi` [leftover] (partial)
- `K:HKLM\SOFTWARE\Classes\MozillaMapi.1` [leftover] (partial)
- `K:HKLM\SOFTWARE\Clients\Calendar` [leftover]
- `K:HKLM\SOFTWARE\Clients\News` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\m5RsduI8S0G9Wkdj.0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1960` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6452` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6480` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6520` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7864` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8020` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8628` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9740` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9812` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~D78BF5DD33499EC2` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Telemetry|ScreenOnLatestAnalyzedSessionTimestamp` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1871224937-2691627691-3762806239-1000|Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1871224937-2691627691-3762806239-1000|SequenceNumber` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]

### ff-tbafter / purge (71 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_13_21_51_38.etl` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1850.5056.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1850.600.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1850.3380.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1850.3380.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1850.3380.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1850.3380.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_185027_3380-3112.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_185019_5056-8948.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_185019_600-4560.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\LightRainV3[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctD940.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctD941.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctE2F7.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctFB7E.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\f8f05350c84c9d76.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C774119C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\AppID\{4AA657B1-55A0-4715-A4FC-B77A3982B865}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{29F458BE-8866-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{4AA657B1-55A0-4715-A4FC-B77A3982B865}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\MozillaMapi` [leftover]
- `K:HKLM\SOFTWARE\Classes\MozillaMapi.1` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\TLyYDfccHECzLAqH.0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1328` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1596` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2004` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2492` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3120` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4112` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6364` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6532` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6544` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7172` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7260` [leftover]

### vscode-insiders-pair / purge (58 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\a91f847fda3fbb368a5ac7b54ba3538cb4dda0de` [leftover]
- `P:C:\Users\tester\.copilot\chats\473e1cb1-f65f-4578-9d8e-d647b79ffe81` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794596238779-3536.log` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794596238940-10204.log` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794596241978-812.log` [leftover]
- `P:C:\Users\tester\.copilot\session-state\.session-operation-locks\b3619deb-f473-41b0-935b-d8f8cfa2c008.lock` [leftover]
- `P:C:\Users\tester\.copilot\session-state\.session-operation-locks\e4cff30c-c7ed-4998-9095-5d1550c4b930.lock` [leftover]
- `P:C:\Users\tester\.copilot\session-state\b3619deb-f473-41b0-935b-d8f8cfa2c008` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1859.2680.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1859.7604.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1859.228.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1859.228.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1859.228.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1859.228.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_185942_228-8040.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_185934_2680-4836.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_185934_7604-3444.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794596208.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctBF7F.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctBF80.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctC8F7.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctE1CC.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1280` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6512` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7228` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7260` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8680` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8936` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9236` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\996` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo305e7596-668f-44c2-c3e1-dec89b4db13ccom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Control\hivelist|\REGISTRY\WC\Silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware` [leftover]

### vscode-upgrade / purge (62 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1909.2136.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1909.8212.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1910.1588.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1910.1588.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1910.1588.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1910.1588.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-13.1904.8308.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-13.1910.8308.3.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_191006_1588-1044.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_190957_2136-1392.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_190957_8212-948.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794596752.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794596824.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6B73.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6B74.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct751A.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct910C.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1360` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1392` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3568` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4228` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\456` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6272` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6588` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6740` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7232` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7564` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7772` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7800` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8064` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8544` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9704` [leftover]

### ff-reinstall / purge (12 missed)

- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_8_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\600` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]

### vlc / purge (97 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1927.1432.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-13.1927.4704.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1927.916.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-13.1927.916.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-13.1927.916.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-13.1927.916.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-13_192738_916-9772.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_192730_1432-7428.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-13_192730_4704-4424.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct183E.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct3162.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctF72.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctF73.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\DLLHOST.EXE-B2E2041C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-3290E8FC.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-E1DBB6D8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-824BF13F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-9EB1DAB8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-C5EEC15E.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UN.EXE-EF7CF935.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UNINSTALL.EXE-D45B3541.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\VLC.EXE-46412408.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\DVD\shell` [leftover]
- `K:HKLM\SOFTWARE\Classes\VideoLAN.VLCPlugin.2` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers\VLCPlayBlurayOnArrival` [leftover] (partial)
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1200` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1660` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2148` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3536` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\656` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6600` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6608` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6616` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8868` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9356` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9384` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9548` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9736` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\9748` [leftover]
- `K:HKLM\SOFTWARE\MozillaPlugins` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Control Panel\NotifyIconSettings\758016307450396245` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Ext\Stats` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{30BD9A02-CB9A-93FD-A859-09C8803F2346}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{51325390-AE6A-68FC-A315-0950CC83A166}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\VideoLAN` [leftover]

### winmerge / purge (117 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\LightRainV3[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\_iu14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\590aee7bdd69b59b.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\_IU14D2N.TMP-A14F7FAF.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-E1DBB6D8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-7B7B04BA.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-C5EEC15E.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UNINS000.EXE-A951C1D7.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\WINMERGE32BITPLUGINPROXY.EXE-6CB96575.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\WINMERGEU.EXE-EFEC0EF5.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Data\ee` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Index\ActivationKey\rsvs9tt9j6q2mpx3gmeqzrt16ed9yfnseb33995t0x7erve7m710` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\ce` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Application\ca` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\ca^windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\ca^windows.fileExplorerContextMenus` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\Application\ca` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\PackageUser\203` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplicationUserModelId\2^WinMerge_f62ztx9ss5ed4!WinMerge` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\112` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\113` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\114` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\115` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\116` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\117` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\118` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\119` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\11a` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\11b` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\11c` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\11d` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\11e` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\11f` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\120` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\121` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\122` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\123` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\124` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\125` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\126` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\127` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\128` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\129` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\12a` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Data\12b` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Index\UserAndDependentPackageAndDependencyType\2^36^1\112` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Index\UserAndDependentPackageAndDependencyType\2^36^1\113` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\DependencyGraph\Index\UserAndDependentPackageAndDependencyType\2^36^1\114` [leftover]

