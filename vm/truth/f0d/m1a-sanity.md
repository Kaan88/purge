# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/f0d/ambient-f0d.json`.

**Total residual: 95** over 3 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 576 |
| kept_owner | 0 | 0 |
| leftover | 23 | 27 |
| rig | 0 | 0 |
| user_data | 1 | 1 |

random-name differences (normalised away): 2; **residual: 22**

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

residual, only in r0: 13
- `Path:c:\program files (x86)\mozilla maintenance service\maintenanceservice_tmp.exe|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\14b7b9705e64d3daf55e4e380a06974af0870bcb|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\bdba956d11d9c49c34acdcd9e2b473043f6702c0|`
- `Path:c:\users\tester\appdata\local\temp\5eb6.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2236|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3852|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7680|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7832|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8748|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\9192|`
- `RegKey:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\mozilla\firefox|`
- `RegValueChanged:hklm\software\classes\clsid\{1814ceeb-49e2-407f-af99-fa755a7d2607}\inprocserver32|`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\uninstall\mozillamaintenanceservice|estimatedsize`

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 578 |
| kept_owner | 0 | 0 |
| leftover | 16 | 70 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 2; **residual: 58**

residual, only in frozen: 2
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|1`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|2`

residual, only in r0: 56
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\00a0571f2e75bdbdd1a2476a8f894a751bbb6d3d|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\023a60659a674e54ec28181343a64409ed42b400|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\06a78a5645e54b087e1e98212728806a8db91c5a|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\19532a680aa3420e61664931b9ffedfc5a1ba46a|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\1a14dd3bfe79d2677247914a804e7754c6f31697|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\1a7ea54f6ed02a958f65aa2226248734bd56d99a|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\1cfcee50405ebfdb8f11806507aa1b6c09343a88|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\215f421eb2965abeaba336bc872b6baed3ad2929|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\2887af2f91c272cc4829b2ff0238f13b2ae3ebfd|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\344f05eb83af92c40c748463948725251c738c4e|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\3dcc2492699ea5c60c614e1434015b0267bd7746|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\44bee4b0e7a927be8238f640c33f0c6e79595fa3|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\46f0a6a555aa8249a19d8b09f26e6a40c13a5c5c|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\47d65966c7941d8252c2298ad88f740ddb0ec587|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\4be137227be808041a402f9df149ffff608a5748|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\52d3e5e7c1e5c3fee22feea83a42ef2286081f5d|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\5334250fad7dc8c2d38d17ff3be3cd409594f9c1|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\54eb70ce51988452f4fa701e01b7ed8495bc67cb|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\5827c774512d5e22881d612a707453e0a096e7d8|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\67a741815ef358e68feb3b8e940458fb521b99b5|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\67b3cd670047089266e01017085a1b1aae1ad3c6|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\69c2682db33c6e44983cc08652bfe5bba028cfd4|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\6bfde811aa6cd64557cac2f6ed17f2f8ad0e9e6d|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\6d28173a6dd999c35109a6d986801a4ec0b63fdc|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\6f49b764ba4c14539409f00dbb05c076f107d437|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\76ff5e6d53d79431e8b60382495a9791a71809a2|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\7cfd606bab2a9684a0da37a04f593280049fbeb9|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\7e3c47be81abe977d8758241de99fda97af688b5|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\809974c2bf5e9bc2e43c0b1046c18850b345f0e3|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\8101c898b3ce5ce0d474afe8c686e224470a88a4|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\8b8a62ae1c6b40344f83d09edfdd61cc24cddb73|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\913abd8e016add0726f43213787bbe7e6f672c11|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\9bfdb8b6afd9ad819391d25093fa5eafd20f0122|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\9d3fbeca6b2a10d0e11fdd9c82d9effb47b3e2b5|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\a37f8481397ecaf29f2f05c3c436ef3c72c7c9b1|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\add10b66dd86067c30062dcf89638cd28f931adf|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\b1df22f585c4032b1e8104a95a50d797cb7695a0|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\b437bbdccfa9dd6842ec7d4d441e2b728c239365|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\b65222eb0683ab0a8f914814c63380ff1103ef67|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\be22493ae468e0ba43e8a8bb21b6a07f6cd06963|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\c245ed79a11abff174bb64c59d94ae7d8342ee32|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\c28c39b9e0f1ca7e2ad1ad64b398a041c1bd25e4|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\c796a2b023302d94a64906393bebeedfa352f844|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\d881a0a5c39ac9e1776249940a29f3c54c159ada|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\eead82ac70d9422807269eb2da4c7dda2a63df36|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\eeb70461a04f10152892e79a10b8e79d307052a1|`
- `Path:c:\users\tester\appdata\local\temp\76a3.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3236|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4300|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4324|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4788|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5172|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5176|`
- `RegKey:hku\.default\software\microsoft\windows\currentversion\explorer\fileexts\.html|`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|16`
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\ufh\shc|17`

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 569 |
| kept_owner | 0 | 0 |
| leftover | 29 | 44 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 4; **residual: 15**

residual, only in frozen: 0

residual, only in r0: 16
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\052efd195dfac7752f1a205d5ca7be92a0858d7c|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\0e15c296a025b778e59bea398d3274e854f392b8|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\6f52a772029428f3f17f3adb0ae67c2fbfce6a2f|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\a57a73c72be35a4c435220a66aaaa780bdb6d565|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\b0a9cb6a58a8923840820347fdba1d945aa11d2d|`
- `Path:c:\programdata\microsoft\windows defender\scans\rtsigs\data\e3bcc64d8ffbd329541bcc0c9e87d834385301bc|`
- `Path:c:\users\tester\appdata\local\temp\4e5a.tmp|`
- `Path:c:\users\tester\appdata\local\temp\tem8dd9.tmp|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1732|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4260|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7324|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7360|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7892|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8068|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\844|`
- `RegValueChanged:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\shell\bags\1\desktop|iconlayouts`

