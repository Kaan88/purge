# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/f1d/ambient-f1d.json`.

**Total residual: 69** over 3 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 575 |
| kept_owner | 0 | 0 |
| leftover | 23 | 26 |
| rig | 0 | 0 |
| user_data | 1 | 1 |

random-name differences (normalised away): 2; **residual: 21**

residual, only in frozen: 9
- `Path:c:\users\tester\appdata\local\temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip|`
- `RegKey:hklm\software\classes\clsid\{1814ceeb-49e2-407f-af99-fa755a7d2607}|`
- `RegKey:hklm\software\classes\interface\{0d68d6d0-d93d-4d08-a30d-f00dd1f45b24}|`
- `RegKey:hklm\software\classes\interface\{1814ceeb-49e2-407f-af99-fa755a7d2607}|`
- `RegKey:hklm\software\classes\interface\{4e747be5-2052-4265-8af0-8ecad7aad1c0}|`
- `RegKey:hklm\software\mozilla\maintenanceservice|`
- `RegKey:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\mozilla|`
- `RegValue:hklm\software\classes\.shtml|`
- `RegValue:hklm\software\classes\.shtml|content type`

residual, only in r0: 12
- `Path:c:\program files (x86)\mozilla maintenance service\maintenanceservice_tmp.exe|`
- `Path:c:\users\tester\appdata\local\temp\823c.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4144|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5184|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5476|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5692|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5928|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6672|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8416|`
- `RegKey:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\mozilla\firefox|`
- `RegValueChanged:hklm\software\classes\clsid\{1814ceeb-49e2-407f-af99-fa755a7d2607}\inprocserver32|`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\uninstall\mozillamaintenanceservice|estimatedsize`

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 626 |
| kept_owner | 0 | 0 |
| leftover | 16 | 45 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 2; **residual: 33**

residual, only in frozen: 2
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|1`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|2`

residual, only in r0: 31
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\0d57c12aa5b8d6a03f5cf0be37e3e6fcc34a842c|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\16047a09e43c3388478f32747ceb2e8623894bee|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\19626afa2faae44d46d7166e2f246878dfe104d6|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\3e4be6607fa6e49d996e32014a7787915822d05b|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\4169436c4145df87df75a83b3aba6c3ba21648fd|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\51afc2c2555599ef0640f6052e4bb3fd87a2686d|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\55c7cb662dfbd47cf1b0e393a79a045d11735c4c|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\81ca8e4976b282bd306970e03603b937c7c6ee16|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\8bac3e6b8504ae20375a73799b80444a0d41ba64|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\9b469492fd0dfff31dcc0a915629aa43b4110f87|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\a94468ac1161fbf3455743d2f2b3e1b18c9bb372|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\aadfc59a4702d33b060068db85e0ff353df50af7|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\c65b472e8a4a6c890a1fafb6dc5265e966eb6015|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\c70b7f68f2914b919a987951dababcaf377e0550|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\c9e295d7de3120d5f0054cc2b39b8d6c2d5449d0|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\cc0577f88825e4a81e0b2643ed7dc54f6a8063c1|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\ded1f7da80d73cc70f3480bdce7f721359a2153a|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\f2188af296712b25c65d7c6b0d96e22feb6c020b|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\f5b1545a2be39f077b48cf5628394fdbb436f5d1|`
- `Path:c:\users\tester\appdata\local\temp\79c0.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2908|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3132|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3908|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5724|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5840|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7444|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7456|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7608|`
- `RegKey:hku\.default\software\microsoft\windows\currentversion\explorer\fileexts\.html|`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|16`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|17`

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 624 |
| kept_owner | 0 | 0 |
| leftover | 29 | 44 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 4; **residual: 15**

residual, only in frozen: 0

residual, only in r0: 16
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\44b56b36da535c08ef617f32a9613c1d3eaa6ecb|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\582da6d57d3cf9008c9b1039a547366342b42bd3|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\729c620681452b78131f27f9d96a5dcd4ee179f8|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\7e3114bcf5da1e0218a30a082f72082ba715b665|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\939b21f51d60f70be92a52f6a2c2150c0ff9d480|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\fedf4ae53933adaf88d8a3cfde712f1846b777d8|`
- `Path:c:\users\tester\appdata\local\temp\8ebf.tmp|`
- `Path:c:\users\tester\appdata\local\temp\tem2a0a.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2884|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3648|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3800|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3984|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7040|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7256|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7368|`
- `RegValueChanged:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\shell\bags\1\desktop|iconlayouts`

