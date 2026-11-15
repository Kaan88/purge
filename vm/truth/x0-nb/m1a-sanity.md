# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/f0/ambient-f0.json`.

**Total residual: 93** over 3 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## vscode

| label | frozen | r0 |
|---|---|---|
| ambient | 171 | 750 |
| kept_owner | 0 | 0 |
| leftover | 152 | 192 |
| rig | 0 | 1 |
| user_data | 2 | 2 |

random-name differences (normalised away): 14; **residual: 48**

residual, only in frozen: 4
- `RegKey:hklm\software\classes\.log\openwithprogids|`
- `RegKey:hklm\software\classes\.ps1\openwithprogids|`
- `RegKey:hklm\software\classes\.psd1\openwithprogids|`
- `RegKey:hklm\software\classes\.psm1\openwithprogids|`

residual, only in r0: 44
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\common\standaloneupdater-2026-11-13.1451.7972.1.odl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\common\standaloneupdater-2026-11-13.1451.9692.1.odl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\common\nucleus-2026-11-13.1452.8476.1.odl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\common\nucleus-2026-11-13.1452.8476.2.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\local\nucleuslocal-2026-11-13.1452.8476.1.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\unauthenticated\nucleusunauthenticated-2026-11-13.1452.8476.1.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\setup\logs\install_2026-11-13_145204_8476-2172.log|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\setup\logs\standaloneupdate_2026-11-13_145156_7972-2380.log|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\setup\logs\standaloneupdate_2026-11-13_145156_9692-1828.log|`
- `Path:c:\users\tester\appdata\local\microsoft\windows\actioncentercache\microsoft-skydrive-desktop_8_0.png|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\cache\cache_data\f_00001b|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\local storage\leveldb\000010.log|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\local storage\leveldb\000011.ldb|`
- `Path:c:\users\tester\appdata\local\temp\wct1309.tmp|`
- `Path:c:\users\tester\appdata\local\temp\wct2b81.tmp|`
- `Path:c:\users\tester\appdata\local\temp\wctb66.tmp|`
- `Path:c:\users\tester\appdata\local\temp\wctb67.tmp|`
- `RegKey:hklm\software\classes\.log|`
- `RegKey:hklm\software\classes\.ps1|`
- `RegKey:hklm\software\classes\.psd1|`
- `RegKey:hklm\software\classes\.psm1|`
- `RegKey:hklm\software\classes\.xml\openwithprogids|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1536|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2132|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2272|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2404|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4056|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4392|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6092|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6620|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6656|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6660|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8864|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9516|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9592|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9920|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows nt\currentversion\hostactivitymanager\commithistory\microsoftwindows.client.cbs_cw5n1h2txyewy!wmss|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~microsoft.visualstudiocode|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\tuning|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000_classes\local settings\software\microsoft\windows\currentversion\appmodel\systemappdata\microsoftwindows.client.cbs_cw5n1h2txyewy\ham\aui\wmss|`
- `RegValue:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\notifications\settings\microsoft.skydrive.desktop|periodicnotificationcount`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\onedrive\accounts|lastupdate`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\notifications\settings\microsoft.skydrive.desktop|lastnotificationaddedtime`

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 286 |
| kept_owner | 0 | 0 |
| leftover | 16 | 34 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 10; **residual: 22**

residual, only in frozen: 2
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|1`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|2`

residual, only in r0: 20
- `Path:c:\users\tester\appdata\local\microsoft\windows\inetcache\ie\x34ll16v\mostlycloudynight[1].png|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1216|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1356|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3048|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4228|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4840|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5796|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6456|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6464|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6500|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7600|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9628|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9716|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~https://gitforwindows.org/faq|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~microsoft.autogenerated.{0fdd9c6b-656b-0f1f-ab08-b1cdbb7067b3}|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~microsoft.autogenerated.{29591c0f-7c09-b655-c0eb-8544fca7d1de}|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~{6d809377-6af0-444b-8957-a3773f02200e}\git|`
- `RegValue:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\ufh\shc|3`
- `RegValue:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\ufh\shc|4`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\onedrive\accounts|lastupdate`

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 408 |
| kept_owner | 0 | 0 |
| leftover | 29 | 48 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 26; **residual: 23**

residual, only in frozen: 2
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfww-in-block`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfww-out-block`

residual, only in r0: 21
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2188|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2684|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3364|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5700|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6388|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6496|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6648|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6684|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7268|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\740|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7876|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9248|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9572|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~{6d809377-6af0-444b-8957-a3773f02200e}\notepad++|`
- `RegValue:hklm\system\currentcontrolset\control\hivelist|\registry\wc\silo305e7596-668f-44c2-c3e1-dec89b4db13ccom`
- `RegValue:hklm\system\currentcontrolset\control\hivelist|\registry\wc\silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom`
- `RegValue:hklm\system\currentcontrolset\control\hivelist|\registry\wc\silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfwws-1-5-21-1871224937-2691627691-3762806239-1000-in-block`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfwws-1-5-21-1871224937-2691627691-3762806239-1000-out-block`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\shell\bags\1\desktop|iconlayouts`

