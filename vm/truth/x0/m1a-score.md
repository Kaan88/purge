# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 15 | 1379 | 42.9% | 28.3% | 20.9% | 28.2% | 26.5% | 20.9% | 74.0% | 11 | 58 | 24 | 1 | 11 | 11 | 32.0% | 32.4% | 39.2% | 2.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| npp-userfiles | purge | 6 | 41 | 58.5% | 58.5% | 0.0% | 58.5% | 58.5% | 0.0% | - | 0 | 3 | 0 | 0 | 0 | 3 | 3 | 0 | 0 | 0 | 0 |
| git-toolsdir | purge | 8 | 25 | 20.0% | 20.0% | 16.0% | 20.0% | 20.0% | 16.0% | 57.1% | 0 | 3 | 3 | 0 | 0 | 5 | 3 | 0 | 0 | 0 | 0 |
| ff-devedition | purge | 20 | 36 | 52.8% | 13.9% | 11.1% | 30.6% | 13.9% | 11.1% | 100.0% | 0 | 6 | 0 | 0 | 2 | 12 | 6 | 0 | 0 | 2 | 0 |
| vscode-with-user | purge | 4 | 187 | 0.5% | 0.5% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 4 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 |
| git-userstate | purge | 10 | 31 | 16.1% | 16.1% | 16.1% | 16.1% | 16.1% | 16.1% | 50.0% | 0 | 5 | 5 | 0 | 0 | 5 | 5 | 0 | 0 | 0 | 0 |
| thunderbird | purge | 25 | 37 | 29.7% | 24.3% | 16.2% | 27.0% | 24.3% | 16.2% | 100.0% | 10 | 1 | 0 | 0 | 0 | 24 | 1 | 0 | 0 | 0 | 0 |
| ff-tbafter | purge | 12 | 52 | 17.3% | 11.5% | 9.6% | 17.3% | 11.5% | 9.6% | 100.0% | 1 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |
| vscode-userstate | purge | 141 | 184 | 87.0% | 87.0% | 72.3% | 72.8% | 72.8% | 72.3% | 98.5% | 0 | 5 | 2 | 1 | 0 | 136 | 5 | 0 | 0 | 0 | 0 |
| vscode-insiders-pair | purge | 4 | 30 | 6.7% | 6.7% | 0.0% | 6.7% | 6.7% | 0.0% | 100.0% | 0 | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| winmerge | purge | 0 | 50 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vscode-upgrade | purge | 139 | 169 | 81.1% | 81.1% | 79.9% | 81.1% | 81.1% | 79.9% | 100.0% | 0 | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 0 | 0 | 0 |
| ff-esr | purge | 21 | 163 | 85.9% | 1.8% | 1.2% | 1.2% | 1.2% | 0.6% | 25.0% | 0 | 14 | 6 | 0 | 4 | 3 | 14 | 0 | 0 | 4 | 0 |
| vscode-zipcopy | purge | 150 | 191 | 85.9% | 85.3% | 74.3% | 74.9% | 74.3% | 74.3% | 99.3% | 0 | 7 | 1 | 0 | 0 | 143 | 7 | 0 | 0 | 0 | 0 |
| ff-reinstall | purge | 15 | 142 | 85.2% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0 | 10 | 7 | 0 | 5 | 0 | 10 | 0 | 0 | 5 | 0 |
| git-upgrade | purge | 12 | 41 | 17.1% | 17.1% | 17.1% | 17.1% | 17.1% | 17.1% | 58.3% | 0 | 0 | 0 | 0 | 0 | 7 | 0 | 5 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| npp-userfiles | purge | 6/15 40.0% | 16/22 72.7% | 2/3 66.7% | 0/1 0.0% |
| git-toolsdir | purge | 0/8 0.0% | 2/8 25.0% | 3/9 33.3% | 0/0 - |
| ff-devedition | purge | 8/14 57.1% | 1/7 14.3% | 10/13 76.9% | 0/2 0.0% |
| vscode-with-user | purge | 0/34 0.0% | 0/142 0.0% | 0/0 - | 1/11 9.1% |
| git-userstate | purge | 0/8 0.0% | 2/14 14.3% | 3/8 37.5% | 0/1 0.0% |
| thunderbird | purge | 3/11 27.3% | 5/22 22.7% | 3/3 100.0% | 0/1 0.0% |
| ff-tbafter | purge | 2/10 20.0% | 3/24 12.5% | 4/10 40.0% | 0/8 0.0% |
| vscode-userstate | purge | 27/39 69.2% | 133/143 93.0% | 0/2 0.0% | 0/0 - |
| vscode-insiders-pair | purge | 1/18 5.6% | 1/9 11.1% | 0/2 0.0% | 0/1 0.0% |
| winmerge | purge | 0/7 0.0% | 0/29 0.0% | 0/8 0.0% | 0/6 0.0% |
| vscode-upgrade | purge | 1/16 6.2% | 136/147 92.5% | 0/2 0.0% | 0/4 0.0% |
| ff-esr | purge | 137/139 98.6% | 1/9 11.1% | 2/2 100.0% | 0/13 0.0% |
| vscode-zipcopy | purge | 20/35 57.1% | 143/147 97.3% | 0/3 0.0% | 1/6 16.7% |
| ff-reinstall | purge | 121/123 98.4% | 0/7 0.0% | 0/0 - | 0/12 0.0% |
| git-upgrade | purge | 0/10 0.0% | 2/10 20.0% | 5/9 55.6% | 0/12 0.0% |

## Truth labels and ambient removal

- **npp-userfiles**: ambient=226, kept_owner=0, leftover=38, rig=0, user_data=3; ambient: r0-null1 removed 135, r0-null2 removed 138, r0-null3 removed 136
- **git-toolsdir**: ambient=210, kept_owner=0, leftover=25, rig=0, user_data=0; ambient: r0-null1 removed 141, r0-null2 removed 157, r0-null3 removed 141
- **ff-devedition**: ambient=166, kept_owner=3, leftover=30, rig=0, user_data=6; ambient: r0-null1 removed 127, r0-null2 removed 128, r0-null3 removed 130
- **vscode-with-user**: ambient=96, kept_owner=0, leftover=167, rig=1, user_data=20; ambient: r0-null1 removed 49, r0-null2 removed 47, r0-null3 removed 49
- **git-userstate**: ambient=134, kept_owner=0, leftover=31, rig=0, user_data=0; ambient: r0-null1 removed 79, r0-null2 removed 100, r0-null3 removed 82
- **thunderbird**: ambient=187, kept_owner=0, leftover=36, rig=0, user_data=1; ambient: r0-null1 removed 147, r0-null2 removed 148, r0-null3 removed 149
- **ff-tbafter**: ambient=366, kept_owner=31, leftover=51, rig=1, user_data=1; ambient: r0-null1 removed 164, r0-null2 removed 167, r0-null3 removed 166
- **vscode-userstate**: ambient=207, kept_owner=0, leftover=156, rig=0, user_data=28; ambient: r0-null1 removed 118, r0-null2 removed 119, r0-null3 removed 118
- **vscode-insiders-pair**: ambient=142, kept_owner=0, leftover=28, rig=0, user_data=2; ambient: r0-null1 removed 59, r0-null2 removed 60, r0-null3 removed 61
- **winmerge**: ambient=208, kept_owner=0, leftover=50, rig=0, user_data=0; ambient: r0-null1 removed 143, r0-null2 removed 144, r0-null3 removed 142
- **vscode-upgrade**: ambient=254, kept_owner=0, leftover=167, rig=0, user_data=2; ambient: r0-null1 removed 150, r0-null2 removed 151, r0-null3 removed 152
- **ff-esr**: ambient=227, kept_owner=0, leftover=92, rig=1, user_data=71; ambient: r0-null1 removed 61, r0-null2 removed 66, r0-null3 removed 62
- **vscode-zipcopy**: ambient=189, kept_owner=0, leftover=171, rig=0, user_data=20; ambient: r0-null1 removed 99, r0-null2 removed 102, r0-null3 removed 101
- **ff-reinstall**: ambient=263, kept_owner=0, leftover=80, rig=1, user_data=62; ambient: r0-null1 removed 81, r0-null2 removed 81, r0-null3 removed 82
- **git-upgrade**: ambient=379, kept_owner=0, leftover=41, rig=1, user_data=0; ambient: r0-null1 removed 165, r0-null2 removed 190, r0-null3 removed 166

## Danger items

- npp-userfiles / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a
- npp-userfiles / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a` (Likely) - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a
- npp-userfiles / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe
- git-toolsdir / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|Backup` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|Backup
- git-toolsdir / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (Safe, preselected) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe
- git-toolsdir / purge: `P:C:\Users\tester\Tools` (Safe, preselected) - existed in snap0: P:C:\Users\tester\Tools
- ff-devedition / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked) - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-devedition / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-devedition / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-devedition / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- vscode-with-user / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|` (Blocked) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|
- vscode-with-user / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|
- vscode-with-user / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe` (Blocked) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe
- vscode-with-user / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode` (Likely) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode
- git-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch
- git-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\ContosoTools\Settings|GitExecutable` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\ContosoTools\Settings|GitExecutable
- git-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\TortoiseGit|MSysGit` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\TortoiseGit|MSysGit
- git-userstate / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|GIT_SSH|C:\Program Files\Git\usr\bin\ssh.exe` (Safe, preselected) - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|GIT_SSH|C:\Program Files\Git\usr\bin\ssh.exe
- git-userstate / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|Path|C:\Program Files\Git\cmd` (Safe, preselected) - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|Path|C:\Program Files\Git\cmd
- thunderbird / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\Mozilla Thunderbird\thunderbird.exe` (Blocked) - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vscode-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe\shell\open\command|` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe\shell\open\command|
- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.edn` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Classes\.edn
- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.gemspec` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Classes\.gemspec
- vscode-userstate / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe` (Likely) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- ff-esr / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|EC4B88E480B4EF72` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|EC4B88E480B4EF72
- ff-esr / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{E997EB2E-4893-4449-B652-B03B3EA3997E}` (Blocked) - existed in snap0: V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{E997EB2E-4893-4449-B652-B03B3EA3997E}
- ff-esr / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|EC4B88E480B4EF72` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|EC4B88E480B4EF72
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` (Safe, preselected) - existed in snap0: V:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}\ProxyStubClsid32|` (Likely) - existed in snap0: V:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}\ProxyStubClsid32|
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\ProxyStubClsid32|` (Likely) - existed in snap0: V:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\ProxyStubClsid32|
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}\ProxyStubClsid32|` (Likely) - existed in snap0: V:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}\ProxyStubClsid32|
- ff-esr / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` (Likely) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\MaintenanceService
- ff-esr / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk` (Blocked) - existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- ff-esr / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\EC4B88E480B4EF72` (Safe, preselected) - existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\EC4B88E480B4EF72
- vscode-zipcopy / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\Tools\VSCode\Code.exe` (Blocked) - existed in snap0: V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\Tools\VSCode\Code.exe; deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.ApplicationCompany` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.ApplicationCompany
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.FriendlyAppName` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.FriendlyAppName
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|` (Likely) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|
- vscode-zipcopy / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode` (Likely) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode
- vscode-zipcopy / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- ff-reinstall / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` (Safe, preselected) - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID
- ff-reinstall / purge: `K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox
- ff-reinstall / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Safe, preselected) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` (Likely) - existed in snap0: K:HKLM\SOFTWARE\Mozilla\MaintenanceService
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak) - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB` (Safe, preselected) - existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 288 entries left inside (171 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\46855vnr.default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 385 entries left inside (255 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\3y54v7n4.MozillaBackgroundTask-CA9422711AE1A81C-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-esr / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 10 entries left inside (9 existed in snap0), e.g. K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox, V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox|Uninstalled-release, K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox\DllPrefetchExperiment; as a plain delete: existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 196 entries left inside (120 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\7ei109q9.default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 206 entries left inside (131 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\wkdzarco.MozillaBackgroundTask-EC4B88E480B4EF72-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-esr / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 2 entries left inside (2 existed in snap0), e.g. P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\EC4B88E480B4EF72, P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\EC4B88E480B4EF72\parent.lock; as a plain delete: existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates
- ff-reinstall / purge: `K:HKLM\SOFTWARE\WOW6432Node\Mozilla` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 3 entries left inside (3 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox, K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox\TaskBarIDs, V:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox\TaskBarIDs|C:\Program Files\Mozilla Firefox; as a plain delete: existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Mozilla
- ff-reinstall / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 10 entries left inside (10 existed in snap0), e.g. K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox, V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox|Uninstalled-release, K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox\DllPrefetchExperiment; as a plain delete: existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Local\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 178 entries left inside (119 existed in snap0), e.g. P:C:\Users\tester\AppData\Local\Mozilla\Firefox, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles, P:C:\Users\tester\AppData\Local\Mozilla\Firefox\Profiles\0877ax5v.default; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla` (Weak) **would be danger** - not empty after the plan's other removals: 192 entries left inside (130 existed in snap0), e.g. P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles, P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\842zl3ti.MozillaBackgroundTask-308046B0AF4A39CB-defaultagent; as a plain delete: existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla
- ff-reinstall / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates` (Safe, preselected) **would be danger** - not empty after the plan's other removals: 2 entries left inside (2 existed in snap0), e.g. P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB, P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB\parent.lock; as a plain delete: existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| npp-userfiles | purge | 0 | 0 | 3 | 1 | 0 | 0 | 0 |
| git-toolsdir | purge | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| ff-devedition | purge | 0 | 0 | 6 | 1 | 0 | 0 | 0 |
| vscode-with-user | purge | 0 | 0 | 4 | 0 | 0 | 0 | 0 |
| git-userstate | purge | 0 | 0 | 0 | 0 | 5 | 0 | 0 |
| thunderbird | purge | 0 | 0 | 1 | 1 | 0 | 0 | 0 |
| ff-tbafter | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| vscode-userstate | purge | 0 | 1 | 2 | 1 | 1 | 2 | 1 |
| vscode-insiders-pair | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| winmerge | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vscode-upgrade | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| ff-esr | purge | 5 | 0 | 8 | 1 | 1 | 0 | 0 |
| vscode-zipcopy | purge | 1 | 0 | 6 | 1 | 0 | 0 | 0 |
| ff-reinstall | purge | 7 | 0 | 3 | 1 | 0 | 0 | 0 |
| git-upgrade | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

- git-toolsdir / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|Backup` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|Backup
- git-toolsdir / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths\rg.exe
- git-toolsdir / purge: `P:C:\Users\tester\Tools` (Safe, preselected, Quarantine) danger - existed in snap0: P:C:\Users\tester\Tools
- ff-esr / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|EC4B88E480B4EF72` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|EC4B88E480B4EF72
- ff-esr / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|EC4B88E480B4EF72` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|EC4B88E480B4EF72
- ff-esr / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-esr / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\EC4B88E480B4EF72` (Safe, preselected, Quarantine) danger - existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\EC4B88E480B4EF72
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|
- ff-reinstall / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB
- ff-reinstall / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID
- ff-reinstall / purge: `K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox
- ff-reinstall / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB` (Safe, preselected, Quarantine) danger - existed in snap0: P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB

### (1) blocking user data

- vscode-userstate / purge: `P:C:\Program Files\Microsoft VS Code` (Safe, preselected, Quarantine) hit - 

### (2) unticked danger

- npp-userfiles / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|a
- npp-userfiles / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a` (Likely, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList|MRUList|a
- npp-userfiles / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\notepad++.exe
- ff-devedition / purge: `V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe|
- ff-devedition / purge: `K:HKLM\SOFTWARE\Classes\Applications\firefox.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\Applications\firefox.exe
- ff-devedition / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Mozilla\Firefox
- ff-devedition / purge: `K:HKLM\SOFTWARE\Mozilla\Firefox` (Blocked, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- vscode-with-user / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|` (Blocked, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode\shell\open\command|
- vscode-with-user / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|
- vscode-with-user / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe` (Blocked, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe
- vscode-with-user / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode
- thunderbird / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\Mozilla Thunderbird\thunderbird.exe` (Blocked, DeleteValue) danger - deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vscode-userstate / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- ff-esr / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{E997EB2E-4893-4449-B652-B03B3EA3997E}` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules|{E997EB2E-4893-4449-B652-B03B3EA3997E}
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}\ProxyStubClsid32|` (Likely, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}\ProxyStubClsid32|
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\ProxyStubClsid32|` (Likely, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\ProxyStubClsid32|
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}\ProxyStubClsid32|` (Likely, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}\ProxyStubClsid32|
- ff-esr / purge: `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` (Likely, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\MaintenanceService
- ff-esr / purge: `P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk` (Blocked, Quarantine) danger - existed in snap0: P:C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk
- ff-esr / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- vscode-zipcopy / purge: `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\Tools\VSCode\Code.exe` (Blocked, DeleteValue) danger - existed in snap0: V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\Tools\VSCode\Code.exe; deny: Report-only: Background Activity Moderator state belongs to the bam driver.
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.ApplicationCompany` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.ApplicationCompany
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.FriendlyAppName` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache|C:\Users\tester\Tools\VSCode\Code.exe.FriendlyAppName
- vscode-zipcopy / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode|
- vscode-zipcopy / purge: `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode` (Likely, DeleteKey) danger - existed in snap0: K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\vscode
- vscode-zipcopy / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- ff-reinstall / purge: `K:HKLM\SOFTWARE\Mozilla\MaintenanceService` (Likely, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Mozilla\MaintenanceService
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Local\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Local\Mozilla\Firefox
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (2) unticked user data

- npp-userfiles / purge: `P:C:\Users\tester\AppData\Roaming\Notepad++` (Likely, Quarantine) hit - 
- ff-devedition / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- thunderbird / purge: `P:C:\Users\tester\AppData\Roaming\Thunderbird` (Likely, Quarantine) hit - 
- ff-tbafter / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 
- vscode-userstate / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- vscode-insiders-pair / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 
- vscode-upgrade / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) hit - 
- ff-esr / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox
- vscode-zipcopy / purge: `P:C:\Users\tester\AppData\Roaming\Code` (Likely, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Code
- ff-reinstall / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) danger - existed in snap0: P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox

### (3) preexisting_value_ref

- git-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Run|GitAutoFetch
- git-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\ContosoTools\Settings|GitExecutable` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\ContosoTools\Settings|GitExecutable
- git-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\TortoiseGit|MSysGit` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\TortoiseGit|MSysGit
- git-userstate / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|GIT_SSH|C:\Program Files\Git\usr\bin\ssh.exe` (Safe, preselected, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|GIT_SSH|C:\Program Files\Git\usr\bin\ssh.exe
- git-userstate / purge: `S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|Path|C:\Program Files\Git\cmd` (Safe, preselected, EditSegment) danger - existed in snap0: S:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Environment|Path|C:\Program Files\Git\cmd
- vscode-userstate / purge: `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe\shell\open\command|` (Likely, DeleteValue) danger - existed in snap0: V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Applications\Code.exe\shell\open\command|
- ff-esr / purge: `V:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` (Safe, preselected, DeleteValue) danger - existed in snap0: V:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|

### (3) old_empty_ext_key

- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.edn` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\.edn
- vscode-userstate / purge: `K:HKLM\SOFTWARE\Classes\.gemspec` (Safe, preselected, DeleteKey) danger - existed in snap0: K:HKLM\SOFTWARE\Classes\.gemspec

## Missed truth items (first 50 per app and tool; full list in the JSON)

### npp-userfiles / purge (17 missed)

- `P:C:\Program Files\Notepad++\my-notes` [user_data]
- `P:C:\Program Files\Notepad++\session-backup.txt` [user_data]
- `P:C:\ProgramData\Microsoft\Windows\AppRepository\8cca448a-4448-408a-9dbe-d67601bdb863_S-1-5-21-1336749127-99101324-1432799918-1000_1.rslc` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\Content\3B7CEBA4139B7484BAF665AC9E712D61` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\AC\Microsoft\CryptnetUrlCache\MetaData\3B7CEBA4139B7484BAF665AC9E712D61` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\tem8780.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsu1.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\GUP.EXE-7F7956CE.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\NOTEPAD++.EXE-0C41AC7A.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2156` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2912` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4168` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6444` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6564` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7236` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{6Q809377-6NS0-444O-8957-N3773S02200R}\Abgrcnq++\abgrcnq++.rkr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### git-toolsdir / purge (20 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-7HK2V5S046-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\dad0483fccec544.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-34012AF4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-48D35E1C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-BEA120E0.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-93971337.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3028` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3244` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6440` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7424` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7440` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7460` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{97E467B4-98C6-4F19-9588-161B7773D6F6} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{A38B883C-1682-497E-97B0-0A3A9E801682} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{E46787A1-4629-4423-A693-BE1F003B2742} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{7544EFB5-B932-07E6-298E-72885A921128}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{BC58A472-B80D-B8F4-07CF-28B3BBC9EB2B}` [leftover]

### ff-devedition / purge (17 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\profile_count_308046B0AF4A39CB.json` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1608` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4360` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4964` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5800` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7172` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-CA9422711AE1A81C` [leftover]
- `C:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\InProcServer32|` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]

### vscode-with-user / purge (186 missed)

- `P:C:\Users\tester\.copilot\chats\31a79e77-e70c-4586-b598-238363d8d3e2` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794578414439-7480.log` [leftover]
- `P:C:\Users\tester\.copilot\session-state\.session-operation-locks\67577991-a7d4-4ea1-bc95-020e122f31cc.lock` [leftover]
- `P:C:\Users\tester\.copilot\session-state\67577991-a7d4-4ea1-bc95-020e122f31cc` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794578386.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Code\agent-host\local-endpoint\entries\d178a77d143c1a43579dd02bef8f2e3ccbf234296fc0c3fe3084a4e9f1e0315b.json` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\agentSessionData\31a79e77-e70c-4586-b598-238363d8d3e2` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\agentSessionData\837f6015-8fbf-40e8-8c3b-d5c2d9c866fb` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\agentSessionData\default-Y29waWxvdGNsaTovMzFhNzllNzctZTcwYy00NTg2LWI1OTgtMjM4MzYzZDhkM2Uy` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\blob_storage\01465964-63f0-48bb-a472-0eba4a4bce47` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\375263d804736ac5_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\44fa04a154a74580_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\b51f2acc0ca14ca2_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\d089ab2210a2fe6b_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\d8729cfb9e1280dd_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\dd491d11bfc57885_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\CachedData\69047191fc427f2f92828279aae1d90d8eeda7ab\chrome\js\e65744cfee9e5896_0` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Code Cache\electron-preload\86E092DB02BAE6C32E3593AE143594C8D96E8501256B0FAACC09E3C70ED7BFD7-67A64C46445250C0C0E1103FCA3290FE88811449B7F10FD5FBBE5AA8F3AC1EB2.cache` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\code.lock` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Crashpad` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\DIPS-wal` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\Local Storage\leveldb\LOG.old` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\logs\20261113T060009` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\globalStorage\agent-host.db-shm` [user_data]
- `P:C:\Users\tester\AppData\Roaming\Code\User\globalStorage\agent-host.db-wal` [user_data]
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
- `K:HKLM\SOFTWARE\Classes\.cc\OpenWithProgids` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cfg` [leftover]
- `K:HKLM\SOFTWARE\Classes\.cjs` [leftover]
- `K:HKLM\SOFTWARE\Classes\.clj` [leftover]

### git-userstate / purge (26 missed)

- `P:C:\Users\tester\AppData\Local\Temp\is-4369PXNDCM-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7224` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7280` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7344` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8080` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8136` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8160` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8184` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.diff` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gitattributes` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gitignore` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gitmodules` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.patch` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiGitAutoFetch` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

### thunderbird / purge (26 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C774119C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PINGSENDER.EXE-CE23898A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\SVCHOST.EXE-B34B6FD4.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\THUNDERBIRD.EXE-1770C0F6.pf` [leftover]
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
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1524` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2024` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3056` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4996` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5648` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7792` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|SequenceNumber` [leftover]

### ff-tbafter / purge (43 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38` [leftover] (partial)
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\f8f05350c84c9d76.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C6FC1224.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CRASHHELPER.EXE-C774119C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\FIREFOX.EXE-25FC0A66.pf` [leftover]
- `K:HKLM\SOFTWARE\Classes\AppID\{4D7FD4F5-27E8-479A-8DF3-C16C917083A2}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{29F458BE-8866-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{4D7FD4F5-27E8-479A-8DF3-C16C917083A2}` [leftover]
- `K:HKLM\SOFTWARE\Classes\CLSID\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{1814CEEB-49E2-407F-AF99-FA755A7D2607}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}` [leftover]
- `K:HKLM\SOFTWARE\Classes\Interface\{6EDCD38E-8861-11D5-A3DD-00B0D0F3BAA7}` [leftover]
- `K:HKLM\SOFTWARE\Classes\MozillaMapi` [leftover]
- `K:HKLM\SOFTWARE\Classes\MozillaMapi.1` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\false` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4432` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4744` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5736` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7400` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7568` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7860` [leftover]
- `K:HKLM\SOFTWARE\mozilla.org` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|` [leftover]
- `V:HKLM\SOFTWARE\Classes\.shtml|Content Type` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|D78BF5DD33499EC2` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\RunNotification|StartupTNotiMozilla-Firefox-308046B0AF4A39CB` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|D78BF5DD33499EC2` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]

### vscode-userstate / purge (24 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794580203.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6604` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7180` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7188` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7208` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7712` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8000` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8116` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]

### vscode-insiders-pair / purge (28 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\Users\tester\.copilot\chats\10ff627b-bb4b-4de9-8206-a1c0a8e11cd7` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794584657490-7064.log` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794584657596-2372.log` [leftover]
- `P:C:\Users\tester\.copilot\session-state\.session-operation-locks\89095598-e1a8-4f41-93b5-e53248f975ef.lock` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794584629.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1572` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7456` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7572` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7872` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8004` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8020` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

### winmerge / purge (50 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\Users\tester\AppData\Local\Programs\Common` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\_iu14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\590aee7bdd69b59b.customDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\RUNDLL32.EXE-01C0B188.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\WINMERGEU.EXE-EFEC0EF5.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Data\7f` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Activation\Index\ActivationKey\rsvs9tt9j6q2mpx3gmeqzrt16ed9yfnseb33995t0x7erve7m710` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\33` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Application\56` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\56^windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\ApplicationAndCategory\56^windows.fileExplorerContextMenus` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Category\windows.comServer` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationExtension\Index\Category\windows.fileExplorerContextMenus` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\Application\56` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\PackageUser\94` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplicationUserModelId\2^WinMerge_f62ztx9ss5ed4!WinMerge` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\31` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageFamily\Data\31` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageFamily\Index\PackageFamilyName\WinMerge_f62ztx9ss5ed4` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageFamily\Index\PackageSID\S-1-15-2-1836903429-3322058576-3145139426-3635139374-2834500418-1688228657-298390146` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageFamilyUser\Index\PackageFamily\31` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageProperty\Index\Package\33` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageProperty\Index\PackageAndName\33^AllowExternalContent` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageProperty\Index\PackageAndName\33^FileSystemWriteVirtualization` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageProperty\Index\PackageAndName\33^RegistryWriteVirtualization` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1424` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2652` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3712` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3764` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7232` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7580` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7780` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\WinMerge_f62ztx9ss5ed4` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\WinMerge_f62ztx9ss5ed4` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\WinMerge\unins000.exe` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Program Files\WinMerge\WinMergeU.exe` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Temp\_iu14D2N.tmp` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Users\tester\AppData\Local\Temp\is-6V4IR.tmp\winmerge.tmp` [leftover]
- `V:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\JvaqbjfCbjreFuryy\i1.0\cbjrefuryy.rkr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Thingamahoochie.WinMerge` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|\Device\HarddiskVolume4\Windows\System32\cmd.exe` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-1336749127-99101324-1432799918-1000|SequenceNumber` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|State` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|UpdateTimer` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

### vscode-upgrade / purge (32 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794581491.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794581552.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1672` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2076` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2136` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\3672` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4348` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5272` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6776` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\964` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|State` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|UpdateTimer` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

### ff-esr / purge (23 missed)

- `P:C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\Firefox_S-1-5-21-1336749127-99101324-1432799918-1000_shortcuts.ini` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\~nsuA.tmp` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\1160` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2452` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4472` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5332` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8016` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\8076` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKLM\SOFTWARE\mozilla.org\Mozilla|CurrentVersion` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|EC4B88E480B4EF72` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|RP4O88R480O4RS72` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|EC4B88E480B4EF72` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\Shell\Bags\1\Desktop|IconLayouts` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

### vscode-zipcopy / purge (27 missed)

- `P:C:\Users\tester\.copilot\chats\f9070286-82be-4805-aac9-8c2b49af3c6e` [leftover]
- `P:C:\Users\tester\.copilot\logs\process-1794582720075-1568.log` [leftover]
- `P:C:\Users\tester\.copilot\session-state\.session-operation-locks\57ca513a-89a1-40a6-9561-aec928b3a779.lock` [leftover]
- `P:C:\Users\tester\.copilot\session-state\57ca513a-89a1-40a6-9561-aec928b3a779` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794582691.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794582718.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-user-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846014.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846015.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846016.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846018.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-0884601F.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-08846022.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\6544` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\App Paths` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{1E589E9D-8A8D-46D9-A2F9-E6D4F8161EE9} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{A38B883C-1682-497E-97B0-0A3A9E801682} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]
- `V:HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached|{C120DE80-FDE4-49F5-A713-E902EF062B8A} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|State` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|UpdateTimer` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PCT` [leftover]

### ff-reinstall / purge (21 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\4612` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\5288` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7056` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7232` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7672` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated|308046B0AF4A39CB` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|308046O0NS4N39PO` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|308046B0AF4A39CB;PrivateBrowsingAUMID` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

### git-upgrade / purge (34 missed)

- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.P-Eco3PTelDefault.json.bk` [leftover]
- `P:C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\utc.cert.json.bk` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\is-HUTH86S8Z7-uninstall.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\600c39005ac9a5cc.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\b9413fda1ddca9c1.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\bbab4f0ce657b5d0.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\BASH.EXE-E0DADEC9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CYGWIN-CONSOLE-HELPER.EXE-D6E999A9.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\GIT.EXE-65A5E465.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\MINTTY.EXE-3A9BD6BC.pf` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\2888` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7624` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7688` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7828` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7904` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7908` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\TermReason\7968` [leftover]
- `K:HKU\S-1-5-19\Software\Microsoft\Cryptography\NGC` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|TvgSbeJvaqbjf.Onfu` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|{6D809377-6AF0-444B-8957-A3773F02200E}\Git\cmd\git-gui.exe` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags|PatchDbUpdateTickCount` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|EndTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|RunCounter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Census|StartTimeBin` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State|AutoUpdateLastSuccessTime` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OneSettings\appcompat\runtimesdbincloud|RefreshAfter` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\AuthCookies\Live\Default\DIDC|Data` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|State` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight|UpdateTimer` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PCT` [leftover]
- `C:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\HAM\AUI\Global.DesktopSpotlight\V1\LU|PTT` [leftover]

