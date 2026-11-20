# Rig score

Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.
`*_nd` recall counts only coverage by offered items that are not `danger`.
Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).
A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).

## Macro (mean over apps per tool)

| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| purge | 3 | 404 | 3.5% | 3.5% | 1.3% | 3.5% | 3.5% | 1.3% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0.0% | 11.1% | 22.2% | 0.0% |

## Per app

| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 1 | 26 | 3.8% | 3.8% | 3.8% | 3.8% | 3.8% | 3.8% | 100.0% | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| python | purge | 2 | 362 | 0.3% | 0.3% | 0.0% | 0.3% | 0.3% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 |
| vcredist | purge | 1 | 16 | 6.2% | 6.2% | 0.0% | 6.2% | 6.2% | 0.0% | - | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |

## Per-kind recall (listed)

| app | tool | Path | RegKey | RegValue | RegValueChanged |
|---|---|---:|---:|---:|---:|
| 7zip | purge | 0/13 0.0% | 1/3 33.3% | 0/1 0.0% | 0/9 0.0% |
| python | purge | 0/38 0.0% | 0/4 0.0% | 1/6 16.7% | 0/314 0.0% |
| vcredist | purge | 0/13 0.0% | 0/1 0.0% | 1/2 50.0% | 0/0 - |

## Truth labels and ambient removal

- **7zip**: ambient=1020, leftover=26, rig=2; ambient: m1bcp-null1 removed 263, m1bcp-null2 removed 194, m1bcp-null3 removed 979
- **python**: ambient=605, kept_owner=29, leftover=361, rig=2, user_data=1; ambient: m1bcp-null1 removed 374, m1bcp-null2 removed 283, m1bcp-null3 removed 526
- **vcredist**: ambient=726, leftover=16, rig=2; ambient: m1bcp-null1 removed 137, m1bcp-null2 removed 136, m1bcp-null3 removed 688

## Danger items

None.

## Delete-if-empty items that stay (noop_if_nonempty)

Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.

- python / purge: `K:HKLM\SOFTWARE\WOW6432Node\Python` (Blocked) **would be danger** - not empty after the plan's other removals: 4 entries left inside (0 existed in snap0), e.g. K:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|, V:HKLM\SOFTWARE\WOW6432Node\Python\PyLauncher|AssociateFiles; as a plain delete: covers kept_owner K:HKLM\SOFTWARE\WOW6432Node\Python

## Reporting classes

(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, e.g. `UFH\SHC|<n>`), offered unticked (Safe or preselected it is blocking). Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.

| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 7zip | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| python | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| vcredist | purge | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

### (1) blocking danger

None.

### (1) blocking user data

None.

### (2) unticked danger

None.

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
| python | purge | 29 | 29 | 100.0% |
| vcredist | purge | 0 | 0 | - |

## Notices (not scored)

`ReportOnly` items that suggest uninstalling a related product (`suggest_uninstall`; ruling 2026-11-18): not an offer and not a listing, so outside every count above. **would be** = how the item would have scored as an ordinary listing.

- python / purge: `K:HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73831AC2-F0E1-4173-9FDB-D07463D7EB80}` suggest uninstall "Python Launcher" (Likely, SYS-BURNDEPS; would be danger: kept_owner K:HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{73831AC2-F0E1-4173-9FDB-D07463D7EB80})

## Missed truth items (first 50 per app and tool; full list in the JSON)

### 7zip / purge (25 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_19_4_1_57.etl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-19.0100.6876.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\4a67ac2c-9508-4977-9660-f152e552475d.e19bf7f2-1246-443d-81ed-99c2a6d03329.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\87fbc65f-e01b-4b09-9598-316d326e14cb.5bdd4067-3763-476a-a81c-2378c4e7ff48.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\9a9a7927-8aee-4820-97eb-2acc84a216a1.686046bb-c681-46ed-b031-c134a364af57.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\acabe54d-ee69-4bb7-996e-77c14ce275a4.cdb99dab-5435-43e5-b75f-43b887dcdeba.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\b15a2291-2a04-4010-bd4b-ba4d41c2cb88.f1c07d6f-b732-4cb3-a375-9ff7be20f725.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\c6cbdc77-5e50-4c77-87b0-c43ef2bc684a.df0d5cdd-30dc-4bdf-9b4e-36bc6ffab879.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct917E.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5bb830f67194431a.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\7ZFM.EXE-44040917.pf` [leftover]
- `P:C:\WINDOWS\System32\Tasks\SoftLanding\S-1-5-21-1871224937-2691627691-3762806239-1000\SoftLandingDeferralTask-{d1ab88d6-0df0-48e9-b996-32a1ea685d5e}` [leftover]
- `P:C:\WINDOWS\System32\Tasks\SoftLanding\S-1-5-21-1871224937-2691627691-3762806239-1000\SoftLandingTriggerTask-128000000001615609-render-{9f30e0c8-898e-479c-92af-610eae7f9ba1}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\c7UulgPePEqxtiiA.0` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\Start\TileProperties\W~{6D809377-6AF0-444B-8957-A3773F02200E}\7-Zip` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\Wbem\WDM\DREDGE|C:\WINDOWS\system32\drivers\battc.sys[BATTCWMI]` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib|Last Counter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib|Last Help` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009|Counter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009|Help` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage|Counter` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage|Help` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\WmiApRpl\Performance|Last Counter` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\WmiApRpl\Performance|Last Help` [leftover]
- `C:HKLM\SYSTEM\CurrentControlSet\Services\WmiApRpl\Performance|Object List` [leftover]

### python / purge (361 missed)

- `P:C:\ProgramData\Microsoft\Windows Defender\Support\MpWppUpdateLogging-20261119-041211.bin` [leftover]
- `P:C:\Users\tester\.idlerc` [user_data]
- `P:C:\Users\tester\AppData\Local\Microsoft\CLR_v4.0` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\CLR_v4.0_32` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\OneDrive\logs\Common\StandaloneUpdater-2026-11-19.0109.8176.1.odl` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\39052a09-3e0a-4740-a656-72b32814bb27.9d4e4042-79c3-4d01-bb27-3334b4aa8524.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\4cd29db2-9930-40bd-9306-a11e958802a1.34dd6a1a-fcfe-48c9-bc9f-f9d0cc2fccdb.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\a06042a8-8933-4c95-ac8b-db175f50b40a.a2677123-3a7a-45f3-af99-398c6b62e554.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\acdd4539-58bd-4f52-98df-68aa9fc2022a.79bbdb8f-23d0-4d27-a4aa-20dd014ba31c.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DEL2D6D.tmp` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_000_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_001_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_002_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_003_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_004_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_005_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_006_launcher_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_007_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119040919_008_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_000_path_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_001_pip_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_002_tcltk_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_003_doc_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_004_lib_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_005_dev_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_006_exe_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\Python 3.12.7 (64-bit)_20261119041228_007_core_AllUsers.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\wct6C6D.tmp` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\97992354503a502a.automaticDestinations-ms` [leftover]
- `P:C:\Users\tester\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\cfa2f398f6b586de.automaticDestinations-ms` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-02663B5A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-71250B2C.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHON.EXE-E3BB012A.pf` [leftover]
- `P:C:\WINDOWS\Prefetch\PYTHONW.EXE-3E88984D.pf` [leftover]
- `P:C:\WINDOWS\System32\Tasks\SoftLanding\S-1-5-21-1871224937-2691627691-3762806239-1000\SoftLandingDeferralTask-{18519b84-4c95-4f08-a7d9-5a15594fd67f}` [leftover]
- `P:C:\WINDOWS\System32\Tasks\SoftLanding\S-1-5-21-1871224937-2691627691-3762806239-1000\SoftLandingTriggerTask-128000000001615609-render-{bded0785-bb9c-405a-a4ae-6b5248069c7a}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SoftLanding\S-1-5-21-1871224937-2691627691-3762806239-1000\SoftLandingDeferralTask-{18519b84-4c95-4f08-a7d9-5a15594fd67f}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SoftLanding\S-1-5-21-1871224937-2691627691-3762806239-1000\SoftLandingTriggerTask-128000000001615609-render-{bded0785-bb9c-405a-a4ae-6b5248069c7a}` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\ServiceInstances\4d1964b7-8ba2-432e-97be-de020987fdce` [leftover]
- `K:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.WindowsAppRuntime.2_8wekyb3d8bbwe` [leftover]
- `V:HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\NGenService\State|LastSuccess` [leftover]
- `V:HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727\NGenService\State|LastSuccess` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{3180B798-1BA6-4D4C-91AE-F0C471E8EA56}\.be\python-3.12.7-amd64.exe` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|3` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows\CurrentVersion\UFH\SHC|4` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\NGenService\Roots|WorkPending` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\NGenService\Roots\AuditPolicyGPManagedStubs.Interop, Version=10.0.0.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=amd64|Status` [leftover]
- `C:HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\NGenService\Roots\AuditPolicyGPManagedStubs.Interop, Version=10.0.0.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=amd64\0|ImageList` [leftover]

### vcredist / purge (15 missed)

- `P:C:\ProgramData\Microsoft\DiagnosticLogCSP\Collectors\DiagnosticLogCSP_Collector_DeviceProvisioning_2026_11_19_5_0_29.etl` [leftover]
- `P:C:\Users\tester\AppData\Local\Microsoft\Windows\WebCache\V0100003.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\513ec7a9-acaf-45a7-a1f6-751f6b61b920.ee8e1497-600d-4f8e-a80d-7bff21cf71be.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\634f77a5-62ba-4f12-9e59-502a418c573e.3770a1bc-a03c-49cb-9e08-b9a7dba26bee.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\648a7179-3aeb-433f-bbea-2c73c725d2a5.717aa4a1-11bd-4165-9930-6c6b1a123979.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\AC\BackgroundTransferApi\974a18a1-5bcf-4851-a746-702c0c4ae1bf.af598ad3-4b08-4e5a-a4a4-4725accfd020.down_meta` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261119045955.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261119045955_000_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261119045955_001_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261119050058.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261119050058_000_vcRuntimeAdditional_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\dd_vcredist_amd64_20261119050058_001_vcRuntimeMinimum_x64.log` [leftover]
- `P:C:\Users\tester\AppData\Local\Temp\DELCFDA.tmp` [leftover]
- `K:HKLM\SOFTWARE\Microsoft\Provisioning\Sessions\5YXmDSol/kargCdQ.0` [leftover]
- `V:HKU\S-1-5-21-1871224937-2691627691-3762806239-1000\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store|C:\Windows\Temp\{FDB24738-3CE3-4256-813A-917E462B82CD}\.be\VC_redist.x64.exe` [leftover]

