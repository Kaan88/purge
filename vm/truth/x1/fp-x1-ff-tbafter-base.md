# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 1 | 80 | 11.2% | 7.5% | 6.2% | 11.2% | 7.5% | 6.2% | 100.0% | 1 | 0 | 0 | 0 | 0 | 0 | 7.1% | 8.8% | 28.6% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | noop_danger | hit | danger | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ff-tbafter | purge | 12 | 80 | 11.2% | 7.5% | 6.2% | 11.2% | 7.5% | 6.2% | 100.0% | 1 | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| ff-tbafter | purge | 2/28 7.1% | 3/34 8.8% | 4/14 28.6% | 0/4 0.0% |

## Truth labels and ambient removal

- **ff-tbafter**: ambient=510, kept_owner=31, leftover=79, rig=1, user_data=1; ambient: f0-null1 removed 376, f0-null2 removed 302, f0-null3 removed 434

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

None.

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it. Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| ff-tbafter | purge | 0 | 0 | 0 | 1 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

None.

### (2) unticked user data

- ff-tbafter / purge: `P:C:\Users\tester\AppData\Roaming\Mozilla\Firefox` (Weak, Quarantine) hit - 

### (3) preexisting_value_ref

None.

### (3) old_empty_ext_key

None.

## Missed truth items (first 50 per app and tool; full list in the JSON)

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

