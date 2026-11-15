# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 16 | 7381 | 15.9% | 11.1% | 9.0% | 13.6% | 10.2% | 9.0% | 92.3% | 13 | 20 | 11 | 31 | 0 | 0 | 0 | 4 | 4 | 17.0% | 20.9% | 9.3% | 0.6% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| git-toolsdir | purge | 6 | 804 | 0.6% | 0.6% | 0.2% | 0.6% | 0.6% | 0.2% | 100.0% | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 5 | 1 | 0 | 0 | 0 | 0 |
| git-userstate | purge | 10 | 64 | 7.8% | 7.8% | 3.1% | 7.8% | 7.8% | 3.1% | 100.0% | 0 | 5 | 0 | 5 | 0 | 0 | 0 | 0 | 5 | 5 | 0 | 0 | 0 | 0 |
| vscode-userstate | purge | 139 | 423 | 38.3% | 38.3% | 31.4% | 31.9% | 31.9% | 31.4% | 100.0% | 0 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 137 | 2 | 0 | 0 | 0 | 0 |
| vscode-zipcopy | purge | 138 | 210 | 71.9% | 71.4% | 63.8% | 64.3% | 63.8% | 63.8% | 100.0% | 0 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 135 | 3 | 0 | 0 | 0 | 0 |
| git-upgrade | purge | 7 | 977 | 0.7% | 0.7% | 0.2% | 0.7% | 0.7% | 0.2% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7 | 0 | 0 | 0 | 0 | 0 |
| npp-userfiles | purge | 6 | 431 | 5.6% | 5.6% | 0.0% | 5.6% | 5.6% | 0.0% | - | 0 | 3 | 0 | 3 | 0 | 0 | 0 | 0 | 3 | 3 | 0 | 0 | 0 | 0 |
| ff-esr | purge | 21 | 71 | 26.8% | 7.0% | 5.6% | 15.5% | 7.0% | 5.6% | 100.0% | 0 | 2 | 5 | 7 | 0 | 0 | 0 | 2 | 12 | 7 | 0 | 0 | 2 | 0 |
| ff-devedition | purge | 21 | 76 | 25.0% | 6.6% | 5.3% | 14.5% | 6.6% | 5.3% | 100.0% | 0 | 3 | 4 | 7 | 0 | 0 | 0 | 2 | 12 | 7 | 0 | 0 | 2 | 0 |
| vscode-with-user | purge | 3 | 202 | 0.5% | 0.5% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 1 | 2 | 3 | 0 | 0 | 0 | 0 | 0 | 3 | 0 | 0 | 0 | 0 |
| thunderbird | purge | 24 | 816 | 1.2% | 1.1% | 0.7% | 1.2% | 1.1% | 0.7% | 100.0% | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 24 | 0 | 0 | 0 | 0 | 0 |
| ff-tbafter | purge | 12 | 837 | 1.1% | 0.7% | 0.6% | 1.1% | 0.7% | 0.6% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| vscode-insiders-pair | purge | 4 | 59 | 3.4% | 3.4% | 0.0% | 3.4% | 3.4% | 0.0% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| vscode-upgrade | purge | 140 | 406 | 34.0% | 34.0% | 33.5% | 34.0% | 34.0% | 33.5% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 140 | 0 | 0 | 0 | 0 | 0 |
| ff-reinstall | purge | 15 | 30 | 36.7% | 0.0% | 0.0% | 36.7% | 0.0% | 0.0% | 0.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 11 |
| vlc | purge | 6 | 1020 | 0.3% | 0.3% | 0.1% | 0.3% | 0.3% | 0.1% | 100.0% | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 0 |
| winmerge | purge | 0 | 955 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| git-toolsdir | purge | 0/20 0.0% | 2/570 0.4% | 3/174 1.7% | 0/40 0.0% |
| git-userstate | purge | 0/25 0.0% | 2/11 18.2% | 3/8 37.5% | 0/20 0.0% |
| vscode-userstate | purge | 28/46 60.9% | 134/164 81.7% | 0/172 0.0% | 0/41 0.0% |
| vscode-zipcopy | purge | 15/37 40.5% | 135/141 95.7% | 0/10 0.0% | 1/22 4.5% |
| git-upgrade | purge | 0/48 0.0% | 2/671 0.3% | 5/197 2.5% | 0/61 0.0% |
| npp-userfiles | purge | 6/45 13.3% | 16/133 12.0% | 2/191 1.0% | 0/62 0.0% |
| ff-esr | purge | 8/23 34.8% | 1/7 14.3% | 10/18 55.6% | 0/23 0.0% |
| ff-devedition | purge | 8/25 32.0% | 1/7 14.3% | 10/22 45.5% | 0/22 0.0% |
| vscode-with-user | purge | 0/38 0.0% | 0/139 0.0% | 0/3 0.0% | 1/22 4.5% |
| thunderbird | purge | 3/26 11.5% | 5/581 0.9% | 2/169 1.2% | 0/40 0.0% |
| ff-tbafter | purge | 2/25 8.0% | 3/593 0.5% | 4/177 2.3% | 0/42 0.0% |
| vscode-insiders-pair | purge | 1/24 4.2% | 1/7 14.3% | 0/8 0.0% | 0/20 0.0% |
| vscode-upgrade | purge | 1/24 4.2% | 137/169 81.1% | 0/172 0.0% | 0/41 0.0% |
| ff-reinstall | purge | 11/18 61.1% | 0/1 0.0% | 0/1 0.0% | 0/10 0.0% |
| vlc | purge | 1/50 2.0% | 0/675 0.0% | 2/238 0.8% | 0/57 0.0% |
| winmerge | purge | 0/28 0.0% | 0/686 0.0% | 0/180 0.0% | 0/61 0.0% |

## Truth labels and ambient removal

- **git-toolsdir**: ambient=930, kept_owner=0, leftover=804, rig=1, user_data=0; ambient: f0-null1 removed 283, f0-null2 removed 226, f0-null3 removed 275
- **git-userstate**: ambient=288, kept_owner=0, leftover=64, rig=2, user_data=0; ambient: f0-null1 removed 230, f0-null2 removed 211, f0-null3 removed 227
- **vscode-userstate**: ambient=1013, kept_owner=0, leftover=394, rig=1, user_data=29; ambient: f0-null1 removed 248, f0-null2 removed 229, f0-null3 removed 243
- **vscode-zipcopy**: ambient=291, kept_owner=0, leftover=195, rig=2, user_data=15; ambient: f0-null1 removed 190, f0-null2 removed 187, f0-null3 removed 206
- **git-upgrade**: ambient=626, kept_owner=1, leftover=977, rig=1, user_data=0; ambient: f0-null1 removed 316, f0-null2 removed 255, f0-null3 removed 498
- **npp-userfiles**: ambient=1034, kept_owner=1, leftover=428, rig=1, user_data=3; ambient: f0-null1 removed 303, f0-null2 removed 229, f0-null3 removed 301
- **ff-esr**: ambient=238, kept_owner=3, leftover=65, rig=2, user_data=6; ambient: f0-null1 removed 177, f0-null2 removed 160, f0-null3 removed 177
- **ff-devedition**: ambient=517, kept_owner=3, leftover=70, rig=2, user_data=6; ambient: f0-null1 removed 230, f0-null2 removed 211, f0-null3 removed 449
- **vscode-with-user**: ambient=525, kept_owner=0, leftover=187, rig=1, user_data=15; ambient: f0-null1 removed 225, f0-null2 removed 209, f0-null3 removed 442
- **thunderbird**: ambient=484, kept_owner=0, leftover=815, rig=1, user_data=1; ambient: f0-null1 removed 303, f0-null2 removed 233, f0-null3 removed 300
- **ff-tbafter**: ambient=705, kept_owner=31, leftover=836, rig=1, user_data=1; ambient: f0-null1 removed 334, f0-null2 removed 260, f0-null3 removed 478
- **vscode-insiders-pair**: ambient=307, kept_owner=0, leftover=57, rig=1, user_data=2; ambient: f0-null1 removed 203, f0-null2 removed 187, f0-null3 removed 207
- **vscode-upgrade**: ambient=1008, kept_owner=0, leftover=404, rig=1, user_data=2; ambient: f0-null1 removed 246, f0-null2 removed 228, f0-null3 removed 239
- **ff-reinstall**: ambient=429, kept_owner=0, leftover=22, rig=2, user_data=8; ambient: f0-null1 removed 153, f0-null2 removed 136, f0-null3 removed 374
- **vlc**: ambient=378, kept_owner=1, leftover=1020, rig=1, user_data=0; ambient: f0-null1 removed 273, f0-null2 removed 200, f0-null3 removed 272
- **winmerge**: ambient=414, kept_owner=0, leftover=955, rig=1, user_data=0; ambient: f0-null1 removed 295, f0-null2 removed 222, f0-null3 removed 287

## Danger items

- git-toolsdir / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH
- git-userstate / purge: `S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd` (Likely) - existed in snap0: S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd
- vscode-userstate / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Likely) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|; replaced: before '"C:\Users\tester\Tools\VSCode\Code.exe" --open-url -- "%1"', after '"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" --open-url -- "%1"'
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
- vscode-with-user / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Blocked) - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|; replaced: before '"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" --open-url -- "%1"', after '"C:\Program Files\Microsoft VS Code\Code.exe" --open-url -- "%1"'
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` (Likely) - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 290 entries left inside (134 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\b9i1ij1o.default-release; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 1463 entries left inside (460 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\2uymdb22.MozillaBackgroundTask-308046B0AF4A39CB-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 307 entries left inside (161 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\2x6e8yva.dev-edition-default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 1405 entries left inside (151 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\c45jrcl0.MozillaBackgroundTask-CA9422711AE1A81C-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla

## Earlier install of the same product in snap0

The run installed and removed the same product before snap0 (run.json `pre`, same ARP key). Offered targets that exist in this snap0 only through that earlier install (absent from the clean run's snap0 / lists-0, last written after it started) are not danger.

- ff-reinstall / purge: clean reference `runs/x2-vscode-upgrade`; 15 offered item(s) not danger for this reason
  - `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB`
  - `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB`
  - `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID`
  - `K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox`
  - `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla\Firefox`
  - `K:HKLM\SOFTWARE\Mozilla\Firefox`
  - `K:HKLM\SOFTWARE\Mozilla\MaintenanceService`
  - `K:HKLM\SOFTWARE\WOW6432Node\Mozilla`
  - `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Mozilla`
  - `P:C:\Users\tester\AppData\Local\Mozilla\Firefox`
  - `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox`
  - `P:C:\Users\tester\AppData\Local\Mozilla`
  - `P:C:\Users\tester\AppData\Roaming\Mozilla`
  - `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB`
  - `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates`

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| git-toolsdir | purge | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| git-userstate | purge | 0 | 0 | 0 | 0 | 5 | 0 | 0 | 0 |
| vscode-userstate | purge | 0 | 0 | 2 | 2 | 0 | 0 | 0 | 0 |
| vscode-zipcopy | purge | 0 | 0 | 2 | 1 | 0 | 0 | 1 | 0 |
| git-upgrade | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| npp-userfiles | purge | 0 | 0 | 3 | 1 | 0 | 0 | 0 | 0 |
| ff-esr | purge | 0 | 0 | 7 | 1 | 0 | 0 | 0 | 0 |
| ff-devedition | purge | 0 | 0 | 7 | 1 | 0 | 0 | 0 | 0 |
| vscode-with-user | purge | 0 | 0 | 2 | 0 | 0 | 0 | 1 | 0 |
| thunderbird | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| ff-tbafter | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| vscode-insiders-pair | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| vscode-upgrade | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| ff-reinstall | purge | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 |
| vlc | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| winmerge | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

- git-toolsdir / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe
- vscode-userstate / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
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
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Applications\Code.exe
- vscode-with-user / purge: `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode

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
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak, RemoveDirIfEmpty) hit - 

### (3) preexisting_value_ref

- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\ContosoTools\Settings|GitExecutable
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\TortoiseGit|MSysGit
- git-userstate / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|GIT_SSH
- git-userstate / purge: `S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd` (Likely, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Environment|Path|C:\Program Files\Git\cmd

### (3) old_empty_ext_key

None.

### (3) replaced_value

- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|; replaced: before '"C:\Users\tester\Tools\VSCode\Code.exe" --open-url -- "%1"', after '"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" --open-url -- "%1"'
- vscode-with-user / purge: `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|` (Blocked, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\vscode\shell\open\command|; replaced: before '"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" --open-url -- "%1"', after '"C:\Program Files\Microsoft VS Code\Code.exe" --open-url -- "%1"'

## Missed truth items (first 50 per app and tool; full list in the JSON)

### git-toolsdir / purge (799 missed)

- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe\AppxBlockMap.xml` [leftover]
- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe\AppxMetadata` [leftover]
- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe\AppxSignature.p7x` [leftover]
- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe\microsoft.system.package.metadata` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0038.9224.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-N1QTW9A7DK-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctC747.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\dad0483fccec544.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-34012AF4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-48D35E1C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-BEA120E0.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-93971337.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Data\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\ExtensionAndName\2eb^com.microsoft.windows.ai.actions` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\Name\com.microsoft.windows.ai.actions\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\d2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\d2^App` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ea` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2eb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ec` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ed` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ee` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ef` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f1` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f3` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f4` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f5` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f6` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f7` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Application\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appExtension` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.appService` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.autoPlayHandler` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileExplorerContextMenus` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.fileTypeAssociation` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\cb^windows.protocol` [leftover]

### git-userstate / purge (59 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\04d8d4f18ec9926414486a1c07b5e14f24a9e669` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\1a63e21e53efbcb359548df13592bdd610eadfb9` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\2c79dd61ef10643f2a919656a9a8a4dcd5411d69` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\34113d6be83885205123015a591ee12667ae076b` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\5718dc68e350397ef09cd3e9fca6a4df9f4d9213` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\5896ab4ab7e9eb95ceafe09bbe23ab54b5abe315` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\ca241c585fb71b64e565816d92012817c598848b` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\e7a06cdc9bdcb0652137689ac2dcebcb3949f6a7` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\fc9377c0c7a9d6e9c754e8618f357888c2715ecc` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\fec7b7d3b9c72fec960f146adcf204cff7e6a54d` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-4G8RN79EM7-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-AC6D43A4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.diff` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.patch` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~https://gitforwindows.org/faq` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\Git` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\IsolationSession|Start` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|IrisActionCreatives` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|_now_` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|Data` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\Metadata|IrisUpdateTimestamp` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.YourPhone_8wekyb3d8bbwe\HAM\AUI\App\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PTT` [leftover]

### vscode-userstate / purge (261 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\a15039baaca17c39c7081a57843eaed2095b3ca5` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.StorePurchaseApp_8wekyb3d8bbwe\LocalState\ims.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794703918.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
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
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WMSS` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\wp-autoplay` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|Hardware` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMDiscoveryTTL` [leftover]

### vscode-zipcopy / purge (59 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\d2779a9a656f9353e23169675cf21e8d97191717` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794704477421-3612.log` [leftover]
- `P:C:\Users\tester\.vscode-shared\sharedStorage\state.vscdb.backup` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794704447.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794704475.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846018.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
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
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|IrisActionCreatives` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|_now_` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|Data` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\Metadata|IrisUpdateTimestamp` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.YourPhone_8wekyb3d8bbwe\HAM\AUI\App\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PTT` [leftover]

### git-upgrade / purge (970 missed)

- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\Codecs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0106.6068.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0106.6068.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0111.3168.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0106.9952.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0106.9952.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-15.0106.9952.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-15.0106.9952.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0106.5032.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0106.5032.2.aodl` [leftover]
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
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-15_010656_9952-6212.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_011108_3168-5740.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Update_2026-11-15_010655_5032-5428.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\ddfdec91220a9dd469b42b9a5caac8a18fa06ebe[1].xml` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-JKMHDB4AK3-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctAC98.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctD5DE.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-8165BDB0.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-AC6D43A4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]

### npp-userfiles / purge (407 missed)

- `P:C:\Program Files\Notepad++\my-notes` [user_data]
- `P:C:\Program Files\Notepad++\session-backup.txt` [user_data]
- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\Codecs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0113.8708.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0113.8708.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0113.4900.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0113.4900.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-15.0113.4900.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-15.0113.4900.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0113.10028.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0113.10028.2.aodl` [leftover]
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
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-15_011357_4900-7504.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Update_2026-11-15_011356_10028-8976.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\ddfdec91220a9dd469b42b9a5caac8a18fa06ebe[1].xml` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\temB49B.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctD3F9.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX77zsthmbxzqveyvr5gqhcfpnd7mfnd5j` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX7tycjjv3satx1c8myac3gpn9ktrwns6b` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXnjayypjpx6dtabtjqtt76hhmg5nsz5nm` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXsywsp6kb3dx2vqg7qaqkbc26sn1pbd28` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3fr\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3g2\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3gp2\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]

### ff-esr / purge (52 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\eb5e226cbdd87df9c824cbe79296364c3c78001e` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\Firefox_S-1-5-21-1871224937-2691627691-3762806239-1000_shortcuts.ini` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_10_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\32e243fd-c670-4568-97d6-9599db6b4541.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|Hardware` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMDiscoveryTTL` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMID` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|SCMID` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|IrisActionCreatives` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|_now_` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|Data` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|State` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\Metadata|IrisUpdateTimestamp` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.YourPhone_8wekyb3d8bbwe\HAM\AUI\App\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.RulesEngine\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.RulesEngine\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WebExperienceHost\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WebExperienceHost\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\HAM\AUI\OobeHost\V1\LU|PCT` [leftover]

### ff-devedition / purge (57 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\9ca8513c8a1b19f27f29884bba0b3f64b5f13671` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0133.2084.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_013300_2084-2072.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_11_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\104cbf12-1536-43e7-ab03-724c8ccd02d6.zip` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct12D4.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
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
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-CA9422711AE1A81C` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
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

### vscode-with-user / purge (201 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\65c7f490e12e0317860fd388b7c4ac144ea73ba2` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794706763769-5544.log` [leftover]
- `P:C:\Users\tester\.vscode-shared\sharedStorage\state.vscdb.backup` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0141.2092.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_014129_2092-3468.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794706737.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct9E3B.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code\blob_storage\2d0c392f-d931-4458-973f-059aed1701fe` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\375263d804736ac5_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\44fa04a154a74580_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\b51f2acc0ca14ca2_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\cf6193f5d019f8a7_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\d8729cfb9e1280dd_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\dd491d11bfc57885_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Code Cache\electron-preload\86E092DB02BAE6C32E3593AE143594C8D96E8501256B0FAACC09E3C70ED7BFD7-67A64C46445250C0C0E1103FCA3290FE88811449B7F10FD5FBBE5AA8F3AC1EB2.cache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Crashpad` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Local Storage\leveldb\LOG.old` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\logs\20261115T043921` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Network\TransportSecurity` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Session Storage` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\globalStorage\state.vscdb.backup` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\workspaceStorage\1794706761962` [user_data]
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
- `K:HKLM\SOFTWARE\Classes\.bash_profile` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bashrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bib` [leftover]
- `K:HKLM\SOFTWARE\Classes\.bowerrc` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c++` [leftover]
- `K:HKLM\SOFTWARE\Classes\.c\OpenWithProgids` [leftover]

### thunderbird / purge (806 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000010.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C774119C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\HELPER.EXE-1A1A68B5.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MAINTENANCESERVICE.EXE-3122AC73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MAINTENANCESERVICE_INSTALLER.-9E296A0C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PINGSENDER.EXE-CE23898A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-E1DBB6D8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNTIMEBROKER.EXE-126F74A7.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-7B7B04BA.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\THUNDERBIRD.EXE-1770C0F6.pf` [leftover]
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
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{BFE0E2A4-C70C-4AD7-AC3D-10D1ECEBB5B4}` [leftover]
- `K:HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{CD349BB6-A2BC-47ED-874F-7185ABA53BD4}` [leftover]
- `K:HKLM\SOFTWARE\Clients\Calendar` [leftover]
- `K:HKLM\SOFTWARE\Clients\News` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Data\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\ExtensionAndName\2eb^com.microsoft.windows.ai.actions` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\AppExtension\Index\Name\com.microsoft.windows.ai.actions\150` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\cb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\d2` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\d2^App` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ea` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2eb` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ec` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ed` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ee` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2ef` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f0` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Data\2f1` [leftover]

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

### vscode-insiders-pair / purge (57 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\e298b815c67b3c5754c3646b851f4ca997d86e9a` [leftover]
- `P:C:\Users\tester\.copilot\chats\03d45dab-0d78-4ba1-a564-8236c6ce3674` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794708213633-2568.log` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794708213704-5964.log` [leftover]
- `P:C:\Users\tester\.copilot\session-state\.session-operation-locks\5b9df605-4fc9-4801-a1a3-c88905e582d3.lock` [leftover]
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
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794708187.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~Microsoft.VisualStudioCode` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.Windows.Photos_2026.11090.22001.0_x64__8wekyb3d8bbwe%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\MrtCache\C:%5CUsers%5Ctester%5CAppData%5CLocal%5CMicrosoft%5COneDrive%5Cresources.pri` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoftwindows.client.oobe_cw5n1h2txyewy\Internet Settings` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|Hardware` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMDiscoveryTTL` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|OEMID` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Store\Configuration|SCMID` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\IrisService|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\RulesEngine\BackgroundData|UpdateTimer` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
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

### vscode-upgrade / purge (268 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\301fec81623829431f2e34059faef74df502849a` [leftover]
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
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794708627.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794708681.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
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

### ff-reinstall / purge (19 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs\Data\9ce254ae7ede3f1f2e401393ca7bfd7b67e74768` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-15.0222.7240.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\StandaloneUpdate_2026-11-15_022204_7240-6332.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\ActionCenterCache\microsoft-skydrive-desktop_9_0.png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Cache\Cache_Data\f_00001b` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6FC.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-1C60E72F.pf` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|PeriodicNotificationCount` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\OneDrive\Accounts|LastUpdate` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop|LastNotificationAddedTime` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\DiscoveryHub\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.IrisService\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.RulesEngine\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\WebExperienceHost\V1\LU|PTT` [leftover]
- `C:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\HAM\AUI\OobeHost\V1\LU|PTT` [leftover]

### vlc / purge (1017 missed)

- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe.xml` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\Codecs` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0227.7416.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0227.7416.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0227.9544.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Common\Nucleus-2026-11-15.0227.9544.2.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\Local\NucleusLocal-2026-11-15.0227.9544.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\ListSync\UnAuthenticated\NucleusUnAuthenticated-2026-11-15.0227.9544.1.aodl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0227.9556.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncEngine-2026-11-15.0227.9556.2.aodl` [leftover]
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
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Install_2026-11-15_022706_9544-9516.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\setup\logs\Update_2026-11-15_022704_9556-9580.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\X34LL16V\ddfdec91220a9dd469b42b9a5caac8a18fa06ebe[1].xml` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctD1E6.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\DLLHOST.EXE-B2E2041C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FILECOAUTH.EXE-BAFA6A88.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FILESYNCCONFIG.EXE-F236F7CB.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\ONEDRIVE.SYNC.SERVICE.EXE-1428190A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-3290E8FC.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-E1DBB6D8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNTIMEBROKER.EXE-126F74A7.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNTIMEBROKER.EXE-F9ED3658.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-67D34FC2.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-7B7B04BA.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-C5EEC15E.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UN.EXE-EF7CF935.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UNINSTALL.EXE-D45B3541.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\VLC.EXE-46412408.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\DVD\shell` [leftover]

### winmerge / purge (955 missed)

- `P:C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\ProgramData\Microsoft\Windows Defender\Scans\RtSigs` [leftover]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.Photos_2026.11090.22001.0_neutral_~_8wekyb3d8bbwe` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\FileCoAuth-2026-11-15.0232.9528.2.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\INetCache\IE\VFNRP0WV\MostlyCloudyNight[1].png` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000011.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000012.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Local Storage\leveldb\000013.ldb` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCache\container.dat` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\INetCookies\ESE` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.OOBE_cw5n1h2txyewy\AC\Microsoft` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\_iu14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wctC217.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\590aee7bdd69b59b.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\_IU14D2N.TMP-A14F7FAF.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\DLLHOST.EXE-08D3C038.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FILECOAUTH.EXE-BAFA6A88.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\REGSVR32.EXE-E1DBB6D8.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNDLL32.EXE-01C0B188.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNTIMEBROKER.EXE-126F74A7.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNTIMEBROKER.EXE-F9ED3658.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-67D34FC2.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-7B7B04BA.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-C5EEC15E.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\UNINS000.EXE-A951C1D7.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\WINMERGE32BITPLUGINPROXY.EXE-6CB96575.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\WINMERGEU.EXE-EFEC0EF5.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX6365235j7azx11tebzeay2a9hd0ngfk5` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX77zsthmbxzqveyvr5gqhcfpnd7mfnd5j` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppX7tycjjv3satx1c8myac3gpn9ktrwns6b` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXnjayypjpx6dtabtjqtt76hhmg5nsz5nm` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\ProgIDs\AppXsywsp6kb3dx2vqg7qaqkbc26sn1pbd28` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3fr\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3g2\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3gp2\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3gp\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.3gpp\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.ari\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.arw\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.asf\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.avci\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.avi\AppXcezf6bjsrpbyaqwyjdehhb46y5e5mm3a` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.avif\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.bay\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.bmp\AppX4mntx4h978m1v9gtzv0ewksfd6pmwsre` [leftover]
- `K:HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Extensions\windows.fileTypeAssociation\.cap\AppXq8btj36kvahvgqpj75d9n4510vjppa26` [leftover]

