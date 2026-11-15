# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/r1/ambient-r1.json`.

**Total residual: 54** over 5 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## vscode

| label | frozen | r0 |
|---|---|---|
| ambient | 171 | 245 |
| kept_owner | 0 | 0 |
| leftover | 152 | 153 |
| rig | 0 | 0 |
| user_data | 2 | 2 |

random-name differences (normalised away): 2; **residual: 1**

residual, only in frozen: 0

residual, only in r0: 1
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason|` (other side: ambient, ambient:exact)

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 207 |
| kept_owner | 0 | 0 |
| leftover | 16 | 30 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 2; **residual: 16**

residual, only in frozen: 1
- `Path:c:\windows\prefetch\git.exe-65a5e465.pf|`

residual, only in r0: 15
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\1500|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2900|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4332|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4784|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5996|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\6820|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7356|`
- `RegKey:hku\s-1-5-19\software\microsoft\cryptography\ngc|`
- `RegValueChanged:hklm\software\microsoft\windows nt\currentversion\appcompatflags|patchdbupdatetickcount`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|endtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|runcounter`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|starttime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|starttimebin`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\installservice\state|autoupdatelastsuccesstime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\onesettings\appcompat\runtimesdbincloud|refreshafter`

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 249 |
| kept_owner | 0 | 0 |
| leftover | 23 | 38 |
| rig | 0 | 1 |
| user_data | 1 | 1 |

random-name differences (normalised away): 2; **residual: 23**

residual, only in frozen: 4
- `Path:c:\users\tester\appdata\local\temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip|`
- `Path:c:\windows\prefetch\crashhelper.exe-c6fc1224.pf|`
- `Path:c:\windows\prefetch\firefox.exe-25fc0a66.pf|`
- `RegKey:hklm\software\classes\clsid\{1814ceeb-49e2-407f-af99-fa755a7d2607}|` (other side: ambient, ambient:pattern ^K:HKLM\\SOFTWARE\\Classes\\CLSID\\\{?[0-9a-f]{8}-[0-9a-f]{4}-[0)

residual, only in r0: 19
- `Path:c:\users\tester\appdata\local\temp\remote-settings-startup-bundle-|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3388|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4812|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5752|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\5840|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7080|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7216|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\808|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8472|`
- `RegKey:hku\s-1-5-19\software\microsoft\cryptography\ngc|`
- `RegKey:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\fileexts\.shtml|`
- `RegValueChanged:hklm\software\microsoft\windows nt\currentversion\appcompatflags|patchdbupdatetickcount`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|endtime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|runcounter`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|starttime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\census|starttimebin`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\installservice\state|autoupdatelastsuccesstime`
- `RegValueChanged:hklm\software\microsoft\windows\currentversion\onesettings\appcompat\runtimesdbincloud|refreshafter`
- `RegValueChanged:hku\s-1-5-20\software\microsoft\windows\currentversion\deliveryoptimization\usage|swarmcount`

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 256 |
| kept_owner | 0 | 0 |
| leftover | 29 | 36 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 4; **residual: 7**

residual, only in frozen: 0

residual, only in r0: 7
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2816|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7540|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8024|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8064|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8096|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8112|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\8136|`

## 7zip

| label | frozen | r0 |
|---|---|---|
| ambient | 89 | 178 |
| kept_owner | 0 | 0 |
| leftover | 3 | 10 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 0; **residual: 7**

residual, only in frozen: 0

residual, only in r0: 7
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\2548|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3016|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3272|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\3444|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4080|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\4772|`
- `RegKey:hklm\software\microsoft\windows\windows error reporting\termreason\7236|`

