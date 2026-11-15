# M1a truth sanity: r0 runs vs frozen M0 truth

Ambient set: `truth/ambient-r0.json`.

**Total residual: 7** over 5 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## vscode

| label | frozen | r0 |
|---|---|---|
| ambient | 171 | 232 |
| kept_owner | 0 | 0 |
| leftover | 152 | 152 |
| rig | 0 | 0 |
| user_data | 2 | 2 |

random-name differences (normalised away): 2; **residual: 0**

residual, only in frozen: 0

residual, only in r0: 0

## git

| label | frozen | r0 |
|---|---|---|
| ambient | 123 | 341 |
| kept_owner | 0 | 0 |
| leftover | 16 | 18 |
| rig | 0 | 1 |
| user_data | 0 | 0 |

random-name differences (normalised away): 2; **residual: 2**

residual, only in frozen: 0

residual, only in r0: 2
- `RegValueChanged:hklm\system\currentcontrolset\control\winlogon\notifications\components\trustedinstaller|events`
- `RegValueChanged:hklm\system\currentcontrolset\services\trustedinstaller|start`

## firefox

| label | frozen | r0 |
|---|---|---|
| ambient | 103 | 156 |
| kept_owner | 0 | 0 |
| leftover | 23 | 22 |
| rig | 0 | 0 |
| user_data | 1 | 1 |

random-name differences (normalised away): 2; **residual: 1**

residual, only in frozen: 1
- `Path:c:\users\tester\appdata\local\temp\2b3e1db9-43ea-48fa-ac1f-48512895ea3c.zip|`

residual, only in r0: 0

## npp

| label | frozen | r0 |
|---|---|---|
| ambient | 167 | 252 |
| kept_owner | 0 | 0 |
| leftover | 29 | 29 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 4; **residual: 0**

residual, only in frozen: 0

residual, only in r0: 0

## 7zip

| label | frozen | r0 |
|---|---|---|
| ambient | 89 | 187 |
| kept_owner | 0 | 0 |
| leftover | 3 | 5 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 0; **residual: 4**

residual, only in frozen: 1
- `Path:c:\windows\prefetch\7zfm.exe-44040917.pf|`

residual, only in r0: 3
- `RegKey:hklm\software\classes\clsid\{0ceb7920-0ce1-49dc-8269-618d1e6ad9c2}|`
- `RegKey:hklm\software\classes\clsid\{dced52c5-2f09-46e0-8e40-2a0880b896f8}|`
- `RegValueChanged:hklm\software\microsoft\sih\sls\{e7a50285-d08d-499d-9ff8-180fdc2332bc}\/sls/{e7a50285-d08d-499d-9ff8-180fdc2332bc}/x64/10.0.26100.1742/0?ch=528&l=en-us&p=&pt=0x81&wua=1308.2408.1052.0&mk=innotek+gmbh&md=virtualbox|expires`

