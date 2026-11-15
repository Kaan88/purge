# M1a truth sanity: r0 runs vs frozen M0 truth

Expected: the same leftover/user_data items except random names. Anything else is investigated before scoring.

## vscode

| label | frozen | r0 |
|---|---|---|
| ambient | 171 | 181 |
| kept_owner | 0 | 0 |
| leftover | 152 | 169 |
| rig | 0 | 0 |
| user_data | 2 | 2 |

only in frozen: 1
- `Path:c:\users\tester\appdata\local\temp\vscode-inno-updater-1794413062.log|`

only in r0: 18
- `Path:c:\programdata\usoshared\logs\user\monotificationux.b4487b1b-47a3-4cde-947d-bb56b906b24a.1.etl|`
- `Path:c:\users\tester\appdata\local\temp\vscode-inno-updater-1794519000.log|`
- `RegKey:hklm\software\microsoft\wbem\tracing\providers\wmiprov @ root/wmi|`
- `RegKey:hku\.default\software\microsoft\windows\currentversion\explorer\fileexts|`
- `RegValueChanged:hklm\software\microsoft\wbem\providers\performance|performance data`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\appx\packagerepair|s-1-5-21-1336749127-99101324-1432799918-1000`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\fcon|puu`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\waasassessment\cache|qualityassessment`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\windowsupdate\orchestrator\scheduler|rebootdowntimeevaluation`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastrefreshattempted`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastrefreshbyapp`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastupdated`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\wosc|lastrefreshattempted`
- `RegValueChanged:hklm\software\microsoft\windowsupdate\ux\statevariables|smartschedulerpredictedendtimepoint`
- `RegValueChanged:hklm\software\microsoft\windowsupdate\ux\statevariables|smartschedulerpredictedstarttimepoint`
- `RegValueChanged:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\advanced|taskbarstatelastrun`
- `RegValueChanged:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\discardable\postsetup\component categories64\{00021492-0000-0000-c000-000000000046}\enum|implementing`

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 149 |
| kept_owner | 0 | 0 |
| leftover | 16 | 63 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

only in frozen: 1
- `Path:c:\users\tester\appdata\local\temp\is-tu8syany8f-uninstall.tmp|`

only in r0: 48
- `Path:c:\programdata\usoshared\logs\user\monotificationux.734b81df-5e5d-4042-a731-c66ca967df4e.1.etl|`
- `Path:c:\users\tester\appdata\local\temp\is-25qw3p3rzp-uninstall.tmp|`
- `RegKey:hklm\software\microsoft\wbem\tracing\providers\wmiprov @ root/wmi|`
- `RegKey:hklm\software\microsoft\windows\currentversion\component based servicing\notifications\optionalfeatures|`
- `RegKey:hklm\software\microsoft\windows\currentversion\component based servicing\removededitionbasedselectableupdates|`
- `RegKey:hklm\software\microsoft\windows\currentversion\component based servicing\sessionspending\31290093_3637032756|`
- `RegValue:hklm\software\microsoft\windows\currentversion\component based servicing\catalogstouninstall|windows-defender-am-default-definitions-package~31bf3856ad364e35~amd64~~10.0.26100.1.cat`
- `RegValueChanged:hklm\software\microsoft\wbem\providers\performance|performance data`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing\notifications|lastmodified_utc`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing\packages\windows-defender-am-default-definitions-optionalwrapper-package~31bf3856ad364e35~amd64~~10.0.26100.1\updates|windows-defender-default-definitions`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|lastmodified_utc`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|nextexecutionsequence`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|sessionidhigh`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|sessionidlow`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowssq|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.app|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.app|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\fcon|puu`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\sidebyside|publisherpolicychangetime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\waasassessment\cache|qualityassessment`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\windowsupdate\orchestrator\scheduler|rebootdowntimeevaluation`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastrefreshattempted`
- ... 8 more

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 138 |
| kept_owner | 0 | 0 |
| leftover | 23 | 63 |
| rig | 0 | 0 |
| user_data | 1 | 1 |

only in frozen: 2
- `Path:c:\users\tester\appdata\local\temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip|`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\firewallrules|{ac21d679-a9c1-47a0-b96f-a0625a9ee822}`

only in r0: 42
- `Path:c:\programdata\usoshared\logs\user\monotificationux.05d60055-49dd-41e0-bf1f-72fa80b79dfc.1.etl|`
- `Path:c:\users\tester\appdata\local\temp\3ddc32a2-a0e4-4c94-9bf6-3b156af82df8.zip|`
- `RegKey:hklm\software\microsoft\wbem\tracing\providers\wmiprov @ root/wmi|`
- `RegKey:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\fileexts\.shtml|`
- `RegValue:hklm\system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\firewallrules|{7f8dfa21-0546-4d87-88e2-b375b105c019}`
- `RegValueChanged:hklm\software\microsoft\wbem\providers\performance|performance data`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowssq|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.app|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.app|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack|diagtrackstatus`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\fcon|du`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\fcon|pdu`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\fcon|puu`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\waasassessment\cache|qualityassessment`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\windowsupdate\orchestrator\scheduler|rebootdowntimeevaluation`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastrefreshattempted`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastrefreshbyapp`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|lastupdated`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\waasmedic|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\wosc\client\persistent\clientstate\wosc|lastrefreshattempted`
- `RegValueChanged:hklm\software\microsoft\windowsupdate\ux\statevariables|smartschedulerpredictedendtimepoint`
- `RegValueChanged:hklm\software\microsoft\windowsupdate\ux\statevariables|smartschedulerpredictedstarttimepoint`
- ... 2 more

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 192 |
| kept_owner | 0 | 0 |
| leftover | 29 | 76 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

only in frozen: 2
- `Path:c:\programdata\microsoft\windows\apprepository\fb764295-5706-4eaf-8f28-603f30273874_s-1-5-21-1336749127-99101324-1432799918-1000_1.rslc|`
- `Path:c:\users\tester\appdata\local\temp\tem5a6a.tmp|`

only in r0: 49
- `Path:c:\programdata\microsoft\windows\apprepository\0cfaefb8-151e-46e8-b7cd-007cf5330f36_s-1-5-21-1336749127-99101324-1432799918-1000_1.rslc|`
- `Path:c:\programdata\usoshared\logs\user\monotificationux.5c0f2683-7e29-47e1-b4d7-87457949d684.1.etl|`
- `Path:c:\users\tester\appdata\local\temp\temcaf7.tmp|`
- `RegKey:hklm\software\microsoft\windows\currentversion\component based servicing\notifications\optionalfeatures|`
- `RegKey:hklm\software\microsoft\windows\currentversion\component based servicing\removededitionbasedselectableupdates|`
- `RegKey:hklm\software\microsoft\windows\currentversion\component based servicing\sessionspending\31290099_2482631739|`
- `RegValue:hklm\software\microsoft\windows\currentversion\component based servicing\catalogstouninstall|windows-defender-am-default-definitions-package~31bf3856ad364e35~amd64~~10.0.26100.1.cat`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\appx\packagerepair|s-1-5-21-1336749127-99101324-1432799918-1000`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing\notifications|lastmodified_utc`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing\packages\windows-defender-am-default-definitions-optionalwrapper-package~31bf3856ad364e35~amd64~~10.0.26100.1\updates|windows-defender-default-definitions`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|lastmodified_utc`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|nextexecutionsequence`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|sessionidhigh`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\component based servicing|sessionidlow`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowsdefault|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\telemetry.asm-windowssq|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.aggregators|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.allow|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.app|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.app|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|etag`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|etagqueryparameters`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|lastdownloadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|lastfilewrittentime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack\settingsrequests\utc.tracing|refreshinterval`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack|diagtrackstatus`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\diagnostics\diagtrack|lastsuccessfulrealtimeuploadtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\sidebyside|publisherpolicychangetime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\waasassessment\cache|qualityassessment`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\windowsupdate\orchestrator\scheduler|rebootdowntimeevaluation`
- ... 9 more

