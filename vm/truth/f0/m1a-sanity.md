# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/f0/ambient-f0.json`.

**Total residual: 112** over 4 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## vscode

| label | frozen | r0 |
|---|---|---|
| ambient | 171 | 484 |
| kept_owner | 0 | 0 |
| leftover | 152 | 177 |
| rig | 0 | 1 |
| user_data | 2 | 2 |

random-name differences (normalised away): 14; **residual: 33**

residual, only in frozen: 4
- `RegKey:hklm\software\classes\.log\openwithprogids|`
- `RegKey:hklm\software\classes\.ps1\openwithprogids|`
- `RegKey:hklm\software\classes\.psd1\openwithprogids|`
- `RegKey:hklm\software\classes\.psm1\openwithprogids|`

residual, only in r0: 29
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs|`
- `Path:c:\users\tester\appdata\local\microsoft\windows\actioncentercache\microsoft-skydrive-desktop_8_0.png|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\cache\cache_data\f_00001b|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\local storage\leveldb\000010.log|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\local storage\leveldb\000011.ldb|`
- `RegKey:hklm\software\classes\.log|`
- `RegKey:hklm\software\classes\.ps1|`
- `RegKey:hklm\software\classes\.psd1|`
- `RegKey:hklm\software\classes\.psm1|`
- `RegKey:hklm\software\classes\.xml\openwithprogids|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\10232|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1848|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1980|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2016|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3056|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3452|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5252|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5968|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6352|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6660|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6692|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9008|`
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
| ambient | 123 | 444 |
| kept_owner | 0 | 0 |
| leftover | 16 | 45 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 10; **residual: 33**

residual, only in frozen: 2
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|1`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|2`

residual, only in r0: 31
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\common\standaloneupdater-2026-11-13.1403.9360.1.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\common\standaloneupdater-2026-11-13.1403.9516.1.odl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\common\nucleus-2026-11-13.1403.3504.1.odl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\common\nucleus-2026-11-13.1403.3504.2.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\local\nucleuslocal-2026-11-13.1403.3504.1.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\logs\listsync\unauthenticated\nucleusunauthenticated-2026-11-13.1403.3504.1.aodl|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\setup\logs\install_2026-11-13_140335_3504-3496.log|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\setup\logs\standaloneupdate_2026-11-13_140327_9360-3400.log|`
- `Path:c:\users\tester\appdata\local\microsoft\onedrive\setup\logs\standaloneupdate_2026-11-13_140327_9516-9568.log|`
- `Path:c:\users\tester\appdata\local\temp\wct18b9.tmp|`
- `Path:c:\users\tester\appdata\local\temp\wctf727.tmp|`
- `Path:c:\users\tester\appdata\local\temp\wctf728.tmp|`
- `Path:c:\users\tester\appdata\local\temp\wctff76.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\228|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3200|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3488|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6568|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6684|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6824|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6860|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7800|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8612|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8828|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9088|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~https://gitforwindows.org/faq|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~microsoft.autogenerated.{0fdd9c6b-656b-0f1f-ab08-b1cdbb7067b3}|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~microsoft.autogenerated.{29591c0f-7c09-b655-c0eb-8544fca7d1de}|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~{6d809377-6af0-444b-8957-a3773f02200e}\git|`
- `RegValue:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\ufh\shc|3`
- `RegValue:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\ufh\shc|4`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\onedrive\accounts|lastupdate`

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 384 |
| kept_owner | 0 | 0 |
| leftover | 23 | 47 |
| rig | 0 | 1 |
| user_data | 1 | 1 |

random-name differences (normalised away): 14; **residual: 24**

residual, only in frozen: 0

residual, only in r0: 24
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs|`
- `Path:c:\users\tester\appdata\local\microsoft\windows\actioncentercache\microsoft-skydrive-desktop_8_0.png|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\cache\cache_data\f_00001b|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\local storage\leveldb\000010.log|`
- `Path:c:\users\tester\appdata\local\packages\microsoftwindows.client.cbs_cw5n1h2txyewy\localstate\ebwebview\default\local storage\leveldb\000011.ldb|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1660|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2236|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2676|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4520|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5348|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5356|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6288|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6464|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6748|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6756|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6772|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7392|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8344|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\explorer\fileexts\.shtml|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~308046b0af4a39cb;privatebrowsingaumid|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~308046b0af4a39cb|`
- `RegValue:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\notifications\settings\microsoft.skydrive.desktop|periodicnotificationcount`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\onedrive\accounts|lastupdate`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\notifications\settings\microsoft.skydrive.desktop|lastnotificationaddedtime`

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 386 |
| kept_owner | 0 | 0 |
| leftover | 29 | 47 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 26; **residual: 22**

residual, only in frozen: 2
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfww-in-block`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfww-out-block`

residual, only in r0: 20
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\10188|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2156|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2356|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3472|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3660|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3700|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6524|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6676|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6716|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7068|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7372|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7556|`
- `RegKey:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\currentversion\start\tileproperties\w~{6d809377-6af0-444b-8957-a3773f02200e}\notepad++|`
- `RegValue:hklm\system\currentcontrolset\control\hivelist|\registry\wc\silo305e7596-668f-44c2-c3e1-dec89b4db13ccom`
- `RegValue:hklm\system\currentcontrolset\control\hivelist|\registry\wc\silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbcom`
- `RegValue:hklm\system\currentcontrolset\control\hivelist|\registry\wc\silo5ff2464b-3c2d-3a40-87f0-134a6c3947dbsoftware`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfwws-1-5-21-1871224937-2691627691-3762806239-1000-in-block`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\restrictedservices\appiso\firewallrules|notepadplusplus_2247w0b46hfwws-1-5-21-1871224937-2691627691-3762806239-1000-out-block`
- `RegValueChanged:hku\s-1-5-21-1871224937-2691627691-3762806239-1000\software\microsoft\windows\shell\bags\1\desktop|iconlayouts`

