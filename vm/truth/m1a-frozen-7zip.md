# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| bcu | 1 | 3 | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0.0% | 100.0% | - | - |
| purge | 1 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0.0% | 0.0% | - | - |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 7zip | bcu | 20 | 3 | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 33.3% | 100.0% | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 19 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| 7zip | purge | 0/2 0.0% | 0/1 0.0% | 0/0 - | 0/0 - |
| 7zip | bcu | 0/2 0.0% | 1/1 100.0% | 0/0 - | 0/0 - |

## Truth labels and ambient removal

- **7zip**: ambient=89, kept_owner=0, leftover=3, rig=0, user_data=0; ambient: null1 removed 68, null2 removed 66, null3 removed 66

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

### 7zip / purge (3 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `K:HKU\S-1-5-21-1336749127-99101324-1432799918-1000\Software\7-Zip` [leftover]

### 7zip / bcu (2 missed)

- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]

