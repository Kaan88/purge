# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 1 | 154 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0% | 0.0% | 0.0% | - |
| purge | 1 | 154 | 89.0% | 89.0% | 87.7% | 89.0% | 89.0% | 87.7% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 7.7% | 97.8% | 0.0% | - |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vscode | purge | 139 | 154 | 89.0% | 89.0% | 87.7% | 89.0% | 89.0% | 87.7% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 139 | 0 | 0 | 0 | 0 | 0 |
| vscode | bcu | 202 | 154 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 202 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| vscode | purge | 1/13 7.7% | 136/139 97.8% | 0/2 0.0% | 0/0 - |
| vscode | bcu | 0/13 0.0% | 0/139 0.0% | 0/2 0.0% | 0/0 - |

## Truth labels and ambient removal

- **vscode**: ambient=171, kept_owner=0, leftover=152, rig=0, user_data=2; ambient: null1 removed 74, null2 removed 76, null3 removed 70

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### vscode / purge (17 missed)

- `P:C:\Users\tester\.copilot` [leftover]
- `P:C:\Users\tester\.vscode` [user_data]
- `P:C:\Users\tester\.vscode-shared` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\iu-14D2N.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-inno-updater-1794413062.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\vscode-stable-system-x64` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\1ced32d74a95c7bc.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA71.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA72.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA73.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\CODE.EXE-A5B0DA7F.pf` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\DeveloperTools` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache\Microsoft.VisualStudioCode_8wekyb3d8bbwe` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count|Zvpebfbsg.IvfhnyFghqvbPbqr` [leftover]
- `V:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\Microsoft\Windows\CurrentVersion\Search\JumplistData|Microsoft.VisualStudioCode` [leftover]

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

