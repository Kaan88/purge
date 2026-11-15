# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/ambient-r0.json`.

**Total residual: 186** over 5 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## vscode

| label | frozen | r0 |
|---|---|---|
| ambient | 171 | 239 |
| kept_owner | 0 | 0 |
| leftover | 152 | 159 |
| rig | 0 | 0 |
| user_data | 2 | 2 |

random-name differences (normalised away): 2; **residual: 7**

residual, only in frozen: 0

residual, only in r0: 7
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1348|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1448|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1588|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2572|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4448|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6416|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7736|`

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 146 |
| kept_owner | 0 | 0 |
| leftover | 16 | 162 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 2; **residual: 146**

residual, only in frozen: 0

residual, only in r0: 146
- `Path:c:\program files (x86)\microsoft\edge\application\157.0.4341.57|`
- `Path:c:\program files (x86)\microsoft\edge\application\setupmetrics\4772_13439045029302277_4772.pma|`
- `Path:c:\program files (x86)\microsoft\edge\application\setupmetrics\5656_13439045029466860_5656.pma|`
- `Path:c:\program files (x86)\microsoft\edge\application\setupmetrics\7340_13439045032061088_7340.pma|`
- `Path:c:\program files (x86)\microsoft\edge\application\setupmetrics\7460_13439045029500391_7460.pma|`
- `Path:c:\program files (x86)\microsoft\edgecore\157.0.4341.57|`
- `Path:c:\program files (x86)\microsoft\edgecore\optimized\157.0.4341.57.manifest|`
- `Path:c:\program files (x86)\microsoft\edgeupdate\download\{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}\157.0.4341.57|`
- `Path:c:\program files (x86)\microsoft\edgeupdate\download\{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}\157.0.4341.57|`
- `Path:c:\program files (x86)\microsoft\edgeupdate\install\{78b37294-aa80-4e5f-a64a-948e5800e03f}|`
- `Path:c:\program files (x86)\microsoft\edgeupdate\install\{eae6f728-fd20-4216-8ebc-65cae9f1364a}|`
- `Path:c:\program files (x86)\microsoft\edgewebview\application\157.0.4341.57|`
- `Path:c:\program files (x86)\microsoft\edgewebview\application\setupmetrics\7856_13439045051733835_7856.pma|`
- `RegKey:hklm\software\classes\clsid\{cd6ec556-4122-431b-b2cb-cdd2965f2a26}|`
- `RegKey:hklm\software\classes\clsid\{e795a3e3-b3e2-4957-8e72-b618117992d7}|`
- `RegKey:hklm\software\microsoft\windows\currentversion\appmodel\staterepository\cache\packageuser\data\96|`
- `RegKey:hklm\software\microsoft\windows\currentversion\appmodel\staterepository\cache\packageuser\data\97|`
- `RegKey:hklm\software\microsoft\windows\currentversion\appmodel\staterepository\cache\packageuser\index\user\1\96|`
- `RegKey:hklm\software\microsoft\windows\currentversion\appmodel\staterepository\cache\packageuser\index\user\1\97|`
- `RegKey:hklm\software\microsoft\windows\currentversion\appmodel\staterepository\cache\packageuser\index\userandpackage\1^31\97|`
- `RegKey:hklm\software\microsoft\windows\currentversion\appmodel\staterepository\cache\packageuser\index\userandpackage\1^32\96|`
- `RegKey:hklm\software\microsoft\windows\currentversion\windowsupdate\reporting\rebootwatch|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1048|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1972|`
- `RegKey:hku\s-1-5-19\software\microsoft\cryptography\ngc|`
- `RegValue:hklm\software\microsoft\windows\windows error reporting\runtimeexceptionhelpermodules|c:\program files (x86)\microsoft\edge\application\157.0.4341.57\msedge_wer.dll`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}\currentstate|downloadprogresspercent`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}\currentstate|downloadtimeremainingms`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}\currentstate|installprogresspercent`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}\currentstate|installtimeremainingms`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{56eb18f8-b008-4cbd-b6d2-8c97fe7e9062}|installerprogress`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}\currentstate|downloadprogresspercent`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}\currentstate|downloadtimeremainingms`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}\currentstate|installprogresspercent`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}\currentstate|installtimeremainingms`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\clientstate\{f3017226-fe2a-4295-8bdf-00c3a9a7e4c5}|installerprogress`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\usagestats\daily\counts|cdp_installer_pick_patch`
- `RegValue:hklm\software\wow6432node\microsoft\edgeupdate\usagestats\daily\counts|client_another_update_in_progress`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\firewallrules|{6c5a1f13-d115-4523-abfd-dd11b648f364}`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\firewallrules|{9a3f73f0-85fa-481b-a38d-2b7d60c68c49}`
- `RegValueChanged:hklm\software\classes\clsid\{1fd49718-1d00-4b19-af5f-070af6d5d54c}\inprocserver32|`
- `RegValueChanged:hklm\software\classes\clsid\{3a84f9c2-6164-485c-a7d9-4b27f8ac009e}\inprocserver32|`
- `RegValueChanged:hklm\software\classes\clsid\{4a749f25-a9e2-4cbe-9859-cf7b15255e14}\localserver32|`
- `RegValueChanged:hklm\software\classes\clsid\{4a749f25-a9e2-4cbe-9859-cf7b15255e14}\localserver32|serverexecutable`
- `RegValueChanged:hklm\software\classes\clsid\{628ace20-b77a-456f-a88d-547db6ceedd5}\localserver32|`
- `RegValueChanged:hklm\software\classes\clsid\{628ace20-b77a-456f-a88d-547db6ceedd5}\localserver32|serverexecutable`
- `RegValueChanged:hklm\software\classes\clsid\{7d6fa3e8-2a3b-4c7d-9f4a-8b2e5c9a7f12}\localserver32|`
- `RegValueChanged:hklm\software\classes\clsid\{7d6fa3e8-2a3b-4c7d-9f4a-8b2e5c9a7f12}\localserver32|serverexecutable`
- `RegValueChanged:hklm\software\classes\clsid\{b54934cd-71a6-4698-bdc2-afea5b86504c}\inprocserver32|`
- `RegValueChanged:hklm\software\classes\msedgehtm\application|applicationicon`
- `RegValueChanged:hklm\software\classes\msedgehtm\defaulticon|`
- `RegValueChanged:hklm\software\classes\msedgemht\application|applicationicon`
- `RegValueChanged:hklm\software\classes\msedgemht\defaulticon|`
- `RegValueChanged:hklm\software\classes\msedgepdf\application|applicationicon`
- `RegValueChanged:hklm\software\classes\msedgepdf\defaulticon|`
- `RegValueChanged:hklm\software\classes\typelib\{12b23868-6dcd-4d1a-ad4c-65b0285201fc}\1.0\0\win32|`
- `RegValueChanged:hklm\software\classes\typelib\{12b23868-6dcd-4d1a-ad4c-65b0285201fc}\1.0\0\win64|`
- `RegValueChanged:hklm\software\classes\wow6432node\clsid\{1fd49718-1d00-4b19-af5f-070af6d5d54c}\inprocserver32|`
- `RegValueChanged:hklm\software\classes\wow6432node\clsid\{3a84f9c2-6164-485c-a7d9-4b27f8ac009e}\inprocserver32|`
- `RegValueChanged:hklm\software\microsoft\active setup\installed components\{9459c573-b17a-45ae-9f64-1857b5d58cee}|stubpath`
- ... 86 more

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 258 |
| kept_owner | 0 | 0 |
| leftover | 23 | 45 |
| rig | 0 | 1 |
| user_data | 1 | 1 |

random-name differences (normalised away): 4; **residual: 22**

residual, only in frozen: 0

residual, only in r0: 23
- `RegKey:hklm\software\classes\clsid\{1814ceeb-49e2-407f-af99-fa755a7d2607}|` (other side: leftover, default)
- `RegKey:hklm\software\classes\clsid\{42051705-efbf-4805-bac0-0694133dbeee}|`
- `RegKey:hklm\software\classes\clsid\{bb420d80-f6a5-4abf-a113-3d31e7d1be61}|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4152|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4612|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5892|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7448|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7556|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7760|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7796|`
- `RegKey:hku\s-1-5-19\software\microsoft\cryptography\ngc|`
- `RegValueChanged:hklm\software\microsoft\windows nt\currentversion\appcompatflags|patchdbupdatetickcount`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|endtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|runcounter`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|starttime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|starttimebin`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\installservice\state|autoupdatelastsuccesstime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\onesettings\appcompat\runtimesdbincloud|refreshafter`
- `RegValueChanged:hklm\software\wow6432node\microsoft\edgeupdate\usagestats\daily|lasttransmission`
- `RegValueChanged:hklm\software\wow6432node\microsoft\edgeupdate|ecsexpiryconfig`
- `RegValueChanged:hklm\software\wow6432node\microsoft\edgeupdate|ecsexpirytime`
- `RegValueChanged:hklm\software\wow6432node\microsoft\edgeupdate|lastecsetag`
- `RegValueChanged:hklm\software\wow6432node\microsoft\edgeupdate|laststartedau`

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 209 |
| kept_owner | 0 | 0 |
| leftover | 29 | 34 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 4; **residual: 5**

residual, only in frozen: 0

residual, only in r0: 5
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3120|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3860|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7320|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7868|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7964|`

## 7zip

| label | frozen | r0 |
|---|---|---|
| ambient | 89 | 168 |
| kept_owner | 0 | 0 |
| leftover | 3 | 9 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 0; **residual: 6**

residual, only in frozen: 0

residual, only in r0: 6
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1644|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3840|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5152|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5580|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6252|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7204|`

