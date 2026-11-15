# M1a truth sanity: r2 runs vs frozen M0 truth

Ambient set: `truth/r2/ambient-r2.json`.

**Total residual: 10** over 5 run(s).

Expected: the same leftover/user_data items except random names (GUIDs, numbers of 6+ digits and the random part of %TEMP% file names are normalised before the comparison). A **residual** difference is investigated before scoring (m1a.sh stops with exit 3 unless --accept-sanity-diff).

## vscode

| label | frozen | r2 |
|---|---|---|
| ambient | 171 | 353 |
| kept_owner | 0 | 0 |
| leftover | 152 | 153 |
| rig | 0 | 1 |
| user_data | 2 | 2 |

random-name differences (normalised away): 2; **residual: 3**

residual, only in frozen: 1
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\userassist\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\count|zvpebfbsg.ivfhnyfghqvbpbqr`

residual, only in r2: 2
- `RegKey:hklm\software\classes\clsid\{7aac202a-6c82-4aca-8ea6-d1a93a2b3f52}|`
- `RegKey:hklm\software\classes\clsid\{e248f276-d0eb-4caa-aaca-61c6d55b1dd7}|`

## git

| label | frozen | r2 |
|---|---|---|
| ambient | 123 | 260 |
| kept_owner | 0 | 0 |
| leftover | 16 | 17 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 2; **residual: 3**

residual, only in frozen: 1
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\userassist\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\count|tvgsbejvaqbjf.onfu`

residual, only in r2: 2
- `RegKey:hklm\software\classes\clsid\{96449681-04cb-455f-9053-c77f2310212d}|`
- `RegKey:hklm\software\classes\clsid\{e31e7174-2886-421b-8ab9-b981f7f4bebd}|`

## firefox

| label | frozen | r2 |
|---|---|---|
| ambient | 103 | 215 |
| kept_owner | 0 | 0 |
| leftover | 23 | 24 |
| rig | 0 | 0 |
| user_data | 1 | 1 |

random-name differences (normalised away): 4; **residual: 3**

residual, only in frozen: 1
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\userassist\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\count|308046o0ns4n39po`

residual, only in r2: 3
- `RegKey:hklm\software\classes\clsid\{1814ceeb-49e2-407f-af99-fa755a7d2607}|` (other side: leftover, default)
- `RegKey:hklm\software\classes\clsid\{622506a1-3f33-4595-b851-49f627f6434e}|`
- `RegKey:hklm\software\classes\clsid\{d6a6855a-429a-4928-8039-4da34c616c2a}|`

## npp

| label | frozen | r2 |
|---|---|---|
| ambient | 167 | 252 |
| kept_owner | 0 | 0 |
| leftover | 29 | 28 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 4; **residual: 1**

residual, only in frozen: 1
- `RegValue:hku\s-1-5-21-1336749127-99101324-1432799918-1000\software\microsoft\windows\currentversion\explorer\userassist\{cebff5cd-ace2-4f4f-9178-9926f41749ea}\count|{6q809377-6ns0-444o-8957-n3773s02200r}\abgrcnq++\abgrcnq++.rkr`

residual, only in r2: 0

## 7zip

| label | frozen | r2 |
|---|---|---|
| ambient | 89 | 188 |
| kept_owner | 0 | 0 |
| leftover | 3 | 3 |
| rig | 0 | 0 |
| user_data | 0 | 0 |

random-name differences (normalised away): 0; **residual: 0**

residual, only in frozen: 0

residual, only in r2: 0

