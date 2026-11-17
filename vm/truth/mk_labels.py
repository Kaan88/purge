"""Generates vm/truth/labels/_os.json and the generated rules of the per-app label files.

    python -I vm/truth/mk_labels.py vm/truth/labels

_os.json holds the shared OS side effects (label `ambient`). _os-servicing.json holds the Windows servicing
families used by the M1a gate only (SERVICING below; m1a.sh passes it as a second --labels). Each app file keeps
its hand-written rules;
rules this script adds carry `"gen": true` and are replaced on every run. Patterns are written with `/` for
a path separator and turned into an escaped backslash. Rule fields (vm/RIG.md §5): `split` = the rule
labels a container only, its new children become items of their own; `first` = checked before the ambient
set and the ambient rules (an attributable exception to them).
"""
import json
import sys

RB = '\\\\'  # regex for one literal backslash


def rx(s):
    return s.replace('/', RB)


U = r'HKU/(?:S-1-5-21-[0-9-]+|\.DEFAULT)'
UC = r'HKU/(?:S-1-5-21-[0-9-]+_Classes|\.DEFAULT/Software/Classes)'
P = r'C:/Users/[^/]+'
TAIL = r'(/[^|]*)?(\|.*)?$'
AD = '^P:' + P + r'/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/'

OS = [
    ('^P:' + P + r'/AppData/Local/Microsoft/Windows/Caches/\{3DA71D5A-20CC-432F-A115-DFE92379E91F\}\.[^/]*\.db$',
     'Shell/Search per-user cache database, regenerated with a new version suffix whenever the Start menu app list changes.'),
    ('^P:' + P + r'/AppData/LocalLow/Microsoft/CryptnetUrlCache(/.*)?$',
     'CryptoAPI URL cache (CRL/OCSP/AIA downloads) filled while verifying any signed binary; Windows ages it out.'),
    ('^P:' + P + r'/AppData/Roaming/Microsoft/Crypto/RSA(/.*)?$',
     'CryptoAPI user key container; never a cleaner target (deleting one can break certificates).'),
    (AD + r'[0-9a-f]{16}\.automaticDestinations-ms$',
     'Jump-list file whose AppID hash (CRC-64 of the AppID) the rig could not resolve to an exe or AUMID of the app. '
     'Resolved ones are labelled leftover by `first` rules in the app file (FS-JUMPLISTS attributes them the same way).'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/SystemCertificates' + TAIL,
     'Machine certificate stores (root auto-update, pin rules) written while verifying signatures; never a cleaner target.'),
    ('^[KVC]:' + U + '/Software/Microsoft/SystemCertificates' + TAIL,
     'User certificate stores (intermediate CA cache); never a cleaner target.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/UFH' + TAIL, 'UFH (shortcut/usage history) service state.'),
    ('^[KC]:' + U + '/Software/Microsoft/Windows/CurrentVersion/UFH' + TAIL,
     'UFH keys and changed SHC slots (a slot that existed before the install now names another shortcut: editing '
     'it back is not possible, deleting it is danger). New SHC values name the app\'s own shortcut and exe and '
     'stay leftover (REF-ANY).'),
    ('^[KVC]:' + UC + '/Local Settings/MuiCache/[0-9]+' + TAIL,
     'MUI resource-string cache generation key (not the shell MuiCache of exe names, which lives under Local Settings/Software/Microsoft/Windows/Shell/MuiCache).'),
    ('^[KVC]:' + U + '/Software/Microsoft/RestartManager' + TAIL, 'Restart Manager session scratch, created by any MSI/Burn/NSIS session.'),
    (r'^[VC]:HKLM/SYSTEM/CurrentControlSet/Control/Session Manager\|PendingFileRenameOperations$',
     'Boot-time delete queue the uninstaller wrote for locked files; consumed at the next reboot. Purge only appends and removes its own pairs (plan §5 reconcile).'),
    ('^[VC]:' + U + r'/Software/Microsoft/Windows NT/CurrentVersion/AppCompatFlags/Compatibility Assistant/Store\|C:/Windows/System32/msiexec\.exe$',
     'PCA record for msiexec.exe itself.'),
    (r'^[VC]:HKLM/SYSTEM/CurrentControlSet/Control/MUI/StringCacheSettings\|', 'MUI string cache generation counter.'),
    ('^[KVC]:' + U + '/Software/Microsoft/Windows/CurrentVersion/CloudStore' + TAIL, 'CloudStore (Start layout/tiles) blobs; rewritten whenever the app list changes.'),
    ('^[VC]:' + U + r'/Software/Microsoft/Windows/CurrentVersion/Search\|Installed(Win32|Packaged)AppsRevision$', 'Search app-list revision GUID.'),
    ('^[VC]:' + U + r'/Software/Microsoft/Windows/CurrentVersion/Start\|Config$', 'Start menu config blob.'),
    (r'^[VC]:HKLM/SOFTWARE/(WOW6432Node/)?Microsoft/Windows/CurrentVersion/Explorer\|GlobalAssocChangedCounter$', 'Shell association change counter (SHChangeNotify).'),
    ('^[VC]:(HKLM|HKLM/SOFTWARE/WOW6432Node|' + U + r')/(SOFTWARE/)?Microsoft/Windows/CurrentVersion/Explorer/(StartPage|Taskband)\|FavoritesRemovedChanges$',
     'Start/taskband pin bookkeeping counter.'),
    ('^[KVC]:HKLM/SYSTEM/CurrentControlSet/Control/FeatureManagement' + TAIL, 'Feature-flag (velocity) impression telemetry.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows Defender' + TAIL, 'Defender cloud/MAPS state; Tamper Protection guards it anyway.'),
    ('^[KVC]:' + U + '/Software/Microsoft/Windows Defender' + TAIL, 'Defender per-user proxy cache.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows Search' + TAIL, 'Windows Search indexer state (USN positions).'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/IdentityCRL' + TAIL, 'Microsoft account client cache.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/ServicesForNFS' + TAIL, 'NFS client provider key created on first network-provider enumeration.'),
    ('^[VC]:' + U + r'/Software/Microsoft/Windows NT/CurrentVersion/Winlogon\|ParseAutoexec$', 'Winlogon flag rewritten at logon.'),
    ('^[VC]:' + U + r'/Software/Microsoft/Windows/CurrentVersion/Explorer/UserAssist/\{[0-9A-F-]+\}/Count\|HRZR_PGYFRFFVBA$',
     'UserAssist session counter (ROT13 of UEME_CTLSESSION), updated by every launch.'),
    ('^[KVC]:HKLM/SYSTEM/CurrentControlSet/Services/(BITS|VSS)' + TAIL,
     'BITS/VSS service state: BITS switches itself to delayed-auto while jobs are queued; VSS writer diagnostics.'),
    (r'^[VC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/BITS\|', 'BITS performance counter file name.'),
    (r'^[VC]:HKLM/SYSTEM/CurrentControlSet/Services/SharedAccess/Epoch\|', 'Firewall policy epoch counter (increments on any rule change).'),
    (r'^[VC]:HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Notifications\|', 'Notification platform sequence/hash bookkeeping.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/AppModel/(StateChange|StateRepositoryStatus)' + TAIL, 'AppX deployment service counters.'),
    ('^[KVC]:HKLM/SOFTWARE/Classes/Local Settings/Software/Microsoft/Windows/CurrentVersion/AppModel/Deployment' + TAIL, 'AppX deployment service version stamps.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Appx/AppxAllUserStore' + TAIL,
     'All-user AppX store: deprovisioning tombstones and pending-operation records the deployment service keeps after a package '
     'is removed. Report-only (ENGINE_PLAN §1.2: Purge never writes it), like StateRepository.'),
    ('^[KVC]:' + U + '/Software/Microsoft/(Pim|Poom|Unified Store|Unistore|UserData|Spelling|IdentityCRL)' + TAIL,
     'PIM/Unistore, spelling and Microsoft-account client state created by Windows services on first use (Electron spellcheck and notifications trigger them).'),
    ('^P:' + P + r'/AppData/(Local/Comms|Roaming/Microsoft/Spelling|Local/Microsoft/TokenBroker)(/.*)?$',
     'Unistore database, Windows spelling dictionaries and the WAM token cache; OS-owned.'),
    ('^[KVC]:' + U + r'/Software/Microsoft/Windows/CurrentVersion/(ClosedCaptioning|Security and Maintenance|Notifications/Settings/Windows\.SystemToast\.[^/|]+)' + TAIL,
     'Accessibility, Security and Maintenance check state and system toast settings.'),
    ('^[VC]:' + U + r'/Software/Microsoft/Windows/CurrentVersion/Explorer(/Package Installation)?\|(GlobalAssocChangedCounter|PackageListVersion)$',
     'Per-user shell association and package list counters.'),
    ('^[VC]:' + UC + r'/Local Settings/Software/Microsoft/Windows/CurrentVersion/AppModel/SystemAppData/Microsoft\.[^/]+_cw5n1h2txyewy/HAM' + TAIL,
     'Host Activity Manager timestamps for inbox system packages.'),
    ('^K:' + UC + '/Local Settings/Software/Microsoft/Windows/CurrentVersion/AppModel/ShellRefresh$', 'AppX shell refresh marker.'),
    # Moved here from the per-app hand rules (2026-11-15, dirty review): the out-of-sample bases (vlc, thunderbird,
    # winmerge) lacked it, so their bam value counted as a leftover no cleaner may reach (deny list).
    ('^[VC]:HKLM/SYSTEM/CurrentControlSet/Services/bam/State/UserSettings/S-1-5-21-[0-9-]+\\|',
     'Background Activity Moderator execution record kept by the bam driver; report-only, never a cleaner target.'),
]
# Containers: the rule labels the container only; what an app put inside is judged item by item.
SPLIT = [
    ('^K:(HKLM/SOFTWARE/Classes|' + UC + ')/PackagedCom(/(Package|ClassIndex))?$',
     'PackagedCom catalog containers created by the AppX COM catalog on first packaged-COM registration. The package and '
     'CLSID entries inside are the package\'s own (split).'),
    ('^K:' + U + '/Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage(/[^/|]+)?$',
     'FeatureUsage containers created by Explorer on first taskbar use. The per-app values inside are REG-PRIVACY (split).'),
]
OS_VALUES = [
    ('^V:(HKLM/SOFTWARE/Classes|' + UC + r')/PackagedCom\|', 'PackagedCom catalog bookkeeping (MaxInstallOrder).'),
    ('^[KVC]:(HKLM/SOFTWARE/Classes|' + UC + ')/PackagedCom/Package/MaxInstallOrder' + TAIL,
     'PackagedCom catalog install-order counter key (not a package: package keys are named by their full name).'),
    ('^V:' + U + r'/Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage\|', 'FeatureUsage bookkeeping (KeyCreationTime).'),
    ('^V:' + U + r'/Software/Microsoft/Windows/CurrentVersion/Explorer/FeatureUsage/[^/|]+\|Microsoft\.Windows\.',
     'FeatureUsage counters for inbox Windows AUMIDs.'),
]

# Jump-list AppID hashes resolved with CRC-64 (reflected, poly 0x92C64265D32139A4, init all ones, no final xor)
# over the upper-cased UTF-16LE AppID. Checked: Microsoft.Windows.Explorer -> f01b4d95cf55d32a.
JUMP = {
    '7zip': {'5bb830f67194431a': r'{ProgramFilesX64}\7-Zip\7zFM.exe'},
    'vscode': {'1ced32d74a95c7bc': 'Microsoft.VisualStudioCode'},
    'git': {'600c39005ac9a5cc': r'{ProgramFilesX64}\Git\cmd\git-gui.exe',
            'b9413fda1ddca9c1': 'Microsoft.AutoGenerated.{29591C0F-7C09-B655-C0EB-8544FCA7D1DE}',
            'bbab4f0ce657b5d0': 'Microsoft.AutoGenerated.{0FDD9C6B-656B-0F1F-AB08-B1CDBB7067B3}'},
    'python': {'97992354503a502a': r'{ProgramFilesX64}\Python312\python.exe',
               'cfa2f398f6b586de': 'Microsoft.AutoGenerated.{401EEA19-A821-9C37-AF46-1F4DFE85DDB9}'},
    'node': {'b37f432ffcc36ce3': r'{ProgramFilesX64}\nodejs\node.exe'},
    # M1b (M1B-RIG-HOST): computed with the same CRC-64 over the known-folder AppID; not yet seen in a capture
    # (whether the launch leaves a jump list at all is confirmed by the m1b-freeze runs).
    'powershell': {'9d5f66f86ab736a4': r'{ProgramFilesX64}\PowerShell\7\pwsh.exe'},
    'python313': {'e724717544c09e92': r'{ProgramFilesX64}\Python313\python.exe'},
}
# Prefetch traces of the app's own executables (FS-PREFETCH: the name plus the path hash are unique).
# Shared system executables (msiexec, dllhost, rundll32, svchost) stay ambient through the app file's
# generic Prefetch rule.
PREFETCH = {
    'npp': ['NOTEPAD\\+\\+', 'GUP'],
    '7zip': ['7ZFM'],
    'vscode': ['CODE'],
    'git': ['BASH', 'CYGWIN-CONSOLE-HELPER', 'GIT', 'MINTTY'],
    'python': ['PYTHON', 'PYTHONW'],
    'firefox': ['FIREFOX', 'CRASHHELPER'],
    'thunderbird': ['THUNDERBIRD'],
    'vlc': ['VLC'],
    'winmerge': ['WINMERGEU'],
    'powershell': ['PWSH'],
    'python313': ['PYTHON', 'PYTHONW'],
}

# Hand rules every MSI or Burn app file of M1b starts with (the same as node.json / vcredist.json): the Windows
# Installer containers and msiexec's restore-point key are the service's own, Prefetch of shared executables and the
# bam record are Windows'.
MSI_AMBIENT = [
    dict(label='ambient', match=rx(r'^K:HKLM/SOFTWARE/Classes/Installer(/(Products|Features|Components|UpgradeCodes|Dependencies|Patches))?$'),
         why='Windows Installer registration containers created by the first MSI install on a clean base and left empty; '
             'owned by the Installer service, not the product.'),
    dict(label='ambient', match=rx(r'^K:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Installer/(Folders|UpgradeCodes|Products|'
                                   r'Components|UserData|UserData/S-1-5-18(/(Products|Components))?)$'),
         why='Windows Installer machine-state containers created on first MSI use; the service\'s own keys.'),
    dict(label='ambient', match=rx(r'^K:HKLM/SOFTWARE/(WOW6432Node/)?Microsoft/Windows NT/CurrentVersion/SystemRestore$'),
         why='msiexec\'s restore-point bookkeeping key (created on the first MSI transaction); Windows state.'),
    dict(label='ambient', match=rx(r'^P:C:/Windows/Prefetch/[^/]+\.pf$'),
         why='SysMain prefetch trace written for any executable that ran (installer, rig); Windows ages them out; not app state.'),
]
BURN_AMBIENT = [
    dict(label='ambient', match=rx(r'^K:HKU/S-1-5-21-[0-9-]+(_Classes/Installer(/Dependencies)?|/Software/Microsoft/Windows/CurrentVersion/RunOnce)$'),
         why='Per-user Windows Installer/Burn container and the RunOnce key Burn creates for reboot resume; left empty.'),
]

# Base label files of the x0 out-of-sample apps (vm/RIG.md section 4b), created with these hand rules when missing
# (informational recall only; review and extend after the first run). Their generated rules come from PREFETCH.
NEW_BASES = {
    'thunderbird': {
        'note': 'Mozilla Thunderbird (x0-thunderbird, also the footprint reference of x0-ff-tbafter). Generic rules only: '
                'informational recall, review after the first run.',
        'rules': [dict(label='user_data', match=rx('^P:' + P + r'/AppData/Roaming/Thunderbird(/.*)?$'),
                       why='Thunderbird profiles (mail, address books): user data.')],
    },
    'vlc': {
        'note': 'VLC media player 3.0.21 (x0-vlc, out-of-sample NSIS). Generic rules only: informational recall.',
        'rules': [dict(label='user_data', match=rx('^P:' + P + r'/AppData/Roaming/vlc(/.*)?$'),
                       why='VLC preferences, playlists and media library: user data.')],
    },
    'winmerge': {
        'note': 'WinMerge 2.16.60 (x0-winmerge, out-of-sample Inno). Generic rules only: informational recall.',
        'rules': [],
    },
}

# The Python Launcher a Python bundle installs and leaves installed (L10). The 3.12.7 launcher's own product code is
# written out in python.json; the 3.13.17 launcher's is not known before a capture, so these rules name only what
# every launcher version shares (UNSURE until the m1b-freeze runs of python313: the shell-extension CLSID and the
# 32-bit WOW6432Node\Python key are taken from the 3.12.7 launcher).
def launcher(who):
    tail = '(/[^|]*)?(\\|.*)?$'
    return [
        dict(label='kept_owner', match=rx(r'^[KVC]:HKLM/SOFTWARE/Classes/\.(py|pyc|pyd|pyo|pyw|pyz|pyzw)' + tail),
             why=f'.py* extension keys of the Python Launcher, still installed ({who}). UNSURE (M1b, no capture yet).'),
        dict(label='kept_owner', match=rx(r'^[KVC]:HKLM/SOFTWARE/Classes/Python\.(File|NoConFile|CompiledFile|ArchiveFile|NoConArchiveFile|Extension)' + tail),
             why=f'Python.* ProgIDs of the Python Launcher, still installed ({who}). UNSURE (M1b, no capture yet).'),
        dict(label='kept_owner', match=rx(r'^[KVC]:HKLM/SOFTWARE/Classes/CLSID/\{BEA218D2-6950-497B-9434-61683EC065FE\}' + tail),
             why=f'The launcher\'s shell drop handler class (CLSID of the 3.12.7 launcher), still installed ({who}). UNSURE.'),
        dict(label='kept_owner', match=rx(r'^[KVC]:HKLM/SOFTWARE/WOW6432Node/Python' + tail),
             why=f'PyLauncher settings of the 32-bit-view launcher keys, still installed ({who}). UNSURE.'),
        dict(label='kept_owner', match=rx(r'^P:C:/Windows/(pyw?\.exe|pyshellext\.amd64\.dll)$'),
             why=f'py.exe, pyw.exe and the shell extension in the Windows directory: launcher files, still installed ({who}).'),
        dict(label='kept_owner', match=rx(r'^P:C:/ProgramData/Package Cache$'),
             why=f'Burn\'s shared package cache root; it still holds the launcher\'s cached package ({who}).'),
    ]


# M1b apps (docs/M1B_DESIGN.json M1B-RIG-HOST). Hand rules only where the design or the installer itself justifies
# them; everything else defaults to leftover (rigtool truth). Frozen after the m1b-freeze runs (vm/truth/FROZEN.md).
NEW_BASES.update({
    'powershell': {
        'note': 'PowerShell 7.6.10 LTS x64 MSI (M1b, M1B-RIG-HOST). Launched once (pwsh.exe -NoLogo). Hand rules: the MSI '
                'containers and the per-user PowerShell folders that hold user data. Not frozen until the two m1b-freeze runs '
                'are reviewed (vm/RIG.md section 12).',
        'rules': MSI_AMBIENT + [
            dict(label='user_data', match=rx('^P:' + P + r'/Documents/PowerShell(/.*)?$'),
                 why='PowerShell 7 per-user profile scripts, modules and help (the user\'s own scripts): user data.'),
            dict(label='user_data', match=rx('^P:' + P + r'/AppData/Roaming/Microsoft/Windows/PowerShell(/.*)?$'),
                 why='PSReadLine history and settings, shared with Windows PowerShell 5.1 (which stays): user data, never '
                     'preselected. UNSURE whether a bare launch writes it.'),
        ],
    },
    'temurin': {
        'note': 'Eclipse Temurin JDK 21.0.13+9 x64 MSI, default features (M1b, M1B-RIG-HOST). Not launched (no GUI exe). '
                'Hand rules: the MSI containers only. Not frozen until the two m1b-freeze runs are reviewed.',
        'rules': list(MSI_AMBIENT),
    },
    'python313': {
        'note': 'Python 3.13.17 x64 (Burn bundle), base of python313-with-312 (M1b, M1B-RIG-HOST). The launcher it installs '
                'stays installed (kept_owner, as python.json L10). Not frozen: the gate scores python313-with-312 only.',
        'rules': launcher('Python 3.13 alone') + MSI_AMBIENT + BURN_AMBIENT + [
            dict(label='user_data', match=rx('^P:' + P + r'/\.idlerc(/.*)?$'),
                 why='IDLE\'s per-user configuration and recent-files list, written by the launch step.'),
        ],
    },
})


def mms(who):
    """kept_owner rules for the shared Mozilla Maintenance Service, which stays installed for `who`."""
    return [
        dict(label='kept_owner', match=rx(r'^P:C:/Program Files \(x86\)/Mozilla Maintenance Service(/.*)?$'),
             why=f'Mozilla Maintenance Service folder: the service stays installed for {who}.'),
        dict(label='kept_owner',
             match=rx('^[KVC]:HKLM/SOFTWARE/(WOW6432Node/)?Microsoft/Windows/CurrentVersion/Uninstall/MozillaMaintenanceService' + TAIL),
             why=f'ARP entry of the Mozilla Maintenance Service, still installed for {who}.'),
        dict(label='kept_owner', match=rx('^[KVC]:HKLM/SOFTWARE/(WOW6432Node/)?Mozilla/MaintenanceService' + TAIL),
             why=f'Mozilla Maintenance Service settings key, still installed for {who}.'),
        dict(label='kept_owner', match=rx('^[KVC]:HKLM/SYSTEM/CurrentControlSet/Services/MozillaMaintenance' + TAIL),
             why=f'MozillaMaintenance service registration, still installed for {who}.'),
    ]

# M1a corpus variants (vm/RIG.md section 4a): label files that reuse a base app's rules through `include`.
# The base file's hand-written and generated rules (jump lists, Prefetch, user data) apply unchanged; rules of
# the variant's own come after them and are kept across regenerations like any hand-written rule.
VARIANTS = {
    'vscode-user': {
        'base': 'vscode',
        'note': 'VS Code per-user build (win32-x64-user), installed at medium integrity into %LOCALAPPDATA%\\Programs. '
                'Same app and user data as the system build, so the vscode rules apply; confirm on the first r0-vscode-user '
                'run that its jump list carries the same AppID hash, and freeze after that review (ENGINE_PLAN 11.1 M1a).',
    },
    'firefox-tb': {
        'base': 'firefox',
        'note': 'The firefox run with Thunderbird installed before snap 0. Everything of Thunderbird\'s (and the shared '
                'Mozilla Maintenance Service, vendor keys and dirs it created) existed in snap 0, so offering it scores '
                'danger by the scorer\'s own rule. What Firefox\'s install added to the Maintenance Service, which stays '
                'installed for Thunderbird (its ARP entry and service are in lists-0 and lists-2), is kept_owner '
                '(generated rules below). Freeze after review of the first r0-firefox-tb run.',
        # The Mozilla Maintenance Service is shared: Thunderbird installed it before snap 0 and still uses it after
        # Firefox is gone (ARP entry MozillaMaintenanceService and service MozillaMaintenance in lists-2). Firefox's
        # installer refreshed it (maintenanceservice_tmp.exe in its folder, a new EstimatedSize on its ARP entry);
        # those changes belong to the still-installed product, not to Firefox. The run's entries_left cannot anchor
        # them because the entry existed before the install.
        'rules': mms('Thunderbird (pre-app)'),
    },
    # ------------------------------------------------------------------ x0 variants (vm/RIG.md section 4b)
    # Planted user files (apps.ps1 plant_post) are user_data: rigtool truth splits a collapsed new install root at
    # them (truth.rs split_kept), so an offer that covers them counts in userdata_preselected / the reporting classes.
    # Everything planted before snap 0 needs no label: it existed in snap 0, so any offer of it scores danger.
    'npp-userfiles': {
        'base': 'npp',
        'note': 'x0 rank 1: npp with a portable copy registered before snap 0 and user files written into the install '
                'folder after the launch (apps.ps1 Plant-NppPortable, Plant-NppUserFiles).',
        'rules': [dict(label='user_data', match=rx(r'^P:C:/Program Files/Notepad\+\+/(my-notes(/.*)?|session-backup\.txt)$'),
                       why='User files planted in the install folder after the launch (plant_post): never the app\'s.')],
    },
    'git-toolsdir': {
        'base': 'git',
        'note': 'x0 rank 2: Git installed into the user\'s existing tools folder %USERPROFILE%\\Tools (planted before snap 0, '
                'so its content scores danger by snap 0). Git\'s own files there are leftover by default; the git rules assume '
                'Program Files\\Git, so recall is partial.',
    },
    'ff-devedition': {
        'base': 'firefox',
        'note': 'x0 rank 3: Firefox Developer Edition installed and launched before snap 0. Its keys, folders and profile '
                'existed in snap 0 (danger when offered); the Maintenance Service it shares is kept_owner.',
        'rules': mms('Firefox Developer Edition (pre-app)'),
    },
    'vscode-with-user': {
        'base': 'vscode',
        'note': 'x0 rank 4: the per-user VS Code installed and launched before snap 0, then the system build removed.',
    },
    'git-userstate': {
        'base': 'git',
        'note': 'x0 rank 5: TortoiseGit and the user\'s own references to Git (config values, PATH, Run values, a Start menu '
                'shortcut, an empty .sh key), all planted before snap 0.',
    },
    'ff-tbafter': {
        'base': 'firefox',
        'note': 'x0 rank 10: Thunderbird installed and launched AFTER Firefox\'s launch (post-app). Its ARP entry and folder '
                'are kept_owner by the lists-2 anchors; the rules below add the Maintenance Service and everything named '
                'Thunderbird. Score the footprint too: truth/footprint.sh x0-ff-tbafter x0-thunderbird.',
        'rules': mms('Thunderbird (post-app)') + [
            dict(label='kept_owner', match=rx(r'(?i)^[PKVC]:.*thunderbird'),
                 why='Thunderbird (post-app, still installed): its keys, folders, ProgIDs, Clients\\Mail and RegisteredApplications entries.'),
        ],
    },
    'vscode-userstate': {
        'base': 'vscode',
        'note': 'x0 rank 11: pre-existing .ext keys, prior VS Code user data and an Open-with registration of a zip copy '
                '(planted before snap 0), and a user file in the install folder after the launch.',
        'rules': [dict(label='user_data', match=rx(r'^P:C:/Program Files/Microsoft VS Code/my-workspace(/.*)?$'),
                       why='User workspace planted in the install folder after the launch (plant_post): never the app\'s.')],
    },
    'vscode-insiders-pair': {
        'base': 'vscode',
        'note': 'x0 rank 13: VS Code Insiders installed and launched before snap 0 (prefix collisions).',
    },
    'vscode-upgrade': {
        'base': 'vscode',
        'note': 'x0 rank 15: VS Code 1.145.0 installed first, the current build over it (both after snap 0).',
    },
    'ff-esr': {
        'base': 'firefox',
        'note': 'x0 rank 16: Firefox ESR in its own folder, installed and launched before snap 0.',
        'rules': mms('Firefox ESR (pre-app)'),
    },
    'vscode-zipcopy': {
        'base': 'vscode-user',
        'note': 'x0 rank 17: an unregistered zip copy of VS Code in %USERPROFILE%\\Tools\\VSCode, started once before snap 0, '
                'then the per-user build installed and removed.',
    },
    'ff-reinstall': {
        'base': 'firefox',
        'note': 'x0 rank 18: Firefox installed, launched and removed with its own uninstaller before snap 0, then installed '
                'again. The first install\'s leftovers existed in snap 0 (danger by the scorer\'s rule; spec Q1).',
    },
    'git-upgrade': {
        'base': 'git',
        'note': 'x0 rank 20: Git 2.56.0 installed first, 2.56.1 over it (both after snap 0).',
    },
    # ------------------------------------------------------------------ M1b variants (M1B-RIG-HOST, gate G2/G3)
    'python312-with-313': {
        'base': 'python',
        'note': 'M1b: Python 3.13.17 installed before snap 0 (pre), then 3.12.7 installed and removed. 3.13 and the launcher '
                'stay. UNSURE: 3.13 installs the newer launcher before snap 0, so the launcher items may not be in the diff at '
                'all (gate K5 expects at least 29 kept_owner items here; check on the first run).',
        'rules': launcher('Python 3.13, installed before snap 0') + [
            dict(label='kept_owner', match=rx(r'^[KVC]:HKLM/SOFTWARE/Python/PythonCore(/[^|]*)?(\|.*)?$'),
                 why='PythonCore container: Python 3.13 (still installed) keeps its 3.13 subkey in it. Only the container and '
                     'shared values; the 3.12 subkey is matched by the rule below first. UNSURE.'),
            dict(label='leftover', first=True, match=rx(r'^[KVC]:HKLM/SOFTWARE/Python/PythonCore/3\.12(/[^|]*)?(\|.*)?$'),
                 why='The removed 3.12\'s own PythonCore subkey.'),
        ],
    },
    'python313-with-312': {
        'base': 'python313',
        'note': 'M1b: Python 3.12.7 installed before snap 0 (pre), then 3.13.17 installed and removed. 3.12 stays; the '
                'launcher (upgraded to 3.13.17 by the 3.13 install) stays for it. UNSURE until the first run.',
        'rules': launcher('Python 3.12, installed before snap 0') + [
            dict(label='kept_owner', match=rx(r'^[KVC]:HKLM/SOFTWARE/Python/PythonCore(/[^|]*)?(\|.*)?$'),
                 why='PythonCore container: Python 3.12 (still installed) keeps its 3.12 subkey in it. UNSURE.'),
            dict(label='leftover', first=True, match=rx(r'^[KVC]:HKLM/SOFTWARE/Python/PythonCore/3\.13(/[^|]*)?(\|.*)?$'),
                 why='The removed 3.13\'s own PythonCore subkey.'),
        ],
    },
    # ------------------------------------------------------------------ dirty-base labels (vm/RIG.md section 4b)
    # dirty-base has Thunderbird and the system VS Code installed (vm/guest/setup-dirty.ps1); m1a.sh maps the f*d
    # runs' firefox and vscode-user to these files (M1A_LABELS in ~/purge-target/campaigns/inbound-dirty-score.sh).
    'firefox-dirty': {
        'base': 'firefox',
        'note': 'firefox on dirty-base: Thunderbird is installed before snap 0 and stays, so the shared Mozilla Maintenance '
                'Service is kept_owner (as firefox-tb). 2026-11-15 dirty review (f2d).',
        'rules': mms('Thunderbird (dirty-base)'),
    },
    'vscode-user-dirty': {
        'base': 'vscode-user',
        'note': 'vscode-user on dirty-base: the system VS Code (C:\\Program Files\\Microsoft VS Code) stays installed and '
                'uses the same per-user data (%APPDATA%\\Code, %USERPROFILE%\\.vscode); what the user build created there '
                'is the still-installed product\'s too. 2026-11-15 dirty review (f2d).',
        'rules': [
            dict(label='kept_owner', match=rx('^P:' + P + r'/(AppData/Roaming/Code|\.vscode)(/.*)?$'),
                 why='VS Code user data shared with the system VS Code, still installed on dirty-base.'),
        ],
    },
}

# M1a gate only (vm/truth/m1a.sh passes this file as a second --labels; the M0 recompute does not, so the frozen
# M0 truth is unchanged). Windows servicing and telemetry families that run on their own schedule, by nature OS
# background activity no uninstaller writes and no cleaner may touch. The primary ambient mechanism is the null
# runs of the same campaign (RIG.md section 6); these rules cover the daily tasks that fire when a restored
# snapshot finds itself a day or more later (stale ambient.json, 2026-11-13 review) but may miss a given null
# run's window. Each rule is anchored under the family's own Windows-owned root; nothing app-named matches.
SERVICING = [
    # Connected User Experiences and Telemetry (DiagTrack): settings downloads (SettingsRequests ETag,
    # LastDownloadTime, RefreshInterval), DiagTrackStatus and upload timestamps, refreshed by the service.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Diagnostics/DiagTrack' + TAIL,
     'DiagTrack (telemetry service) settings refresh and upload bookkeeping; written on the service\'s own schedule.'),
    # Windows Update Medic / settings client (WaaSMedic, WOSC) refresh timestamps.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Wosc' + TAIL,
     'Windows Update settings client (WaaSMedic/WOSC) refresh state.'),
    # Update Session Orchestrator: scheduler state and the UX smart-scheduler predictions.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/WindowsUpdate/Orchestrator' + TAIL,
     'Update Session Orchestrator scheduler state (RebootDowntimeEvaluation...).'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/WindowsUpdate/UX/StateVariables' + TAIL,
     'Windows Update UX smart-scheduler predictions.'),
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/WaaSAssessment' + TAIL,
     'Windows-as-a-Service quality assessment cache.'),
    ('^P:C:/ProgramData/USOShared/Logs(/.*)?$', 'Update Session Orchestrator ETL logs (MoNotificationUx...).'),
    # Component Based Servicing: servicing sessions (e.g. the Defender default-definitions package refresh),
    # session ids, pending sessions, notification stamps, catalogs to uninstall.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Component Based Servicing' + TAIL,
     'Component Based Servicing (TrustedInstaller) session state; the component store is never a cleaner target.'),
    ('^[VC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SideBySide\\|PublisherPolicyChangeTime$',
     'WinSxS publisher-policy change stamp, set by servicing.'),
    ('^[VC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Fcon\\|',
     'Feature configuration (Fcon) update stamps (PUU, DU, PDU).'),
    # WMI: provider tracing registrations and the ADAP performance-library refresh (WmiApSrv).
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Wbem/(Tracing|PROVIDERS/Performance)' + TAIL,
     'WMI provider tracing registration and ADAP performance data refresh; WMI\'s own state.'),
    ('^[VC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Appx/PackageRepair\\|',
     'AppX package-repair bookkeeping per user (deployment service maintenance task).'),
    ('^P:C:/ProgramData/Microsoft/Windows Defender/Scans/History(/.*)?$',
     'Microsoft Defender scan history store (results of its own scheduled and real-time scans).'),
    # The next three were approved by the user on 2026-11-14 (blocked pending approval on 2026-11-13). Each is
    # limited to the exact Windows-internal locations seen in the r0/r1/f1d/x1 sanity residuals and truths.
    # TrustedInstaller session state: the Windows Modules Installer service's start type and its Winlogon
    # notification flags, flipped by servicing sessions. Changed values only, these two names only.
    ('^C:HKLM/SYSTEM/CurrentControlSet/(Services/TrustedInstaller\\|Start|Control/Winlogon/Notifications/Components/TrustedInstaller\\|Events)$',
     'TrustedInstaller (Windows Modules Installer) session state: service start type and Winlogon notification events '
     'toggled by servicing (approved 2026-11-14).'),
    # SIH (Service Initiated Healing, sihclient.exe): the Windows Update self-healing client's cached service-locator
    # responses, one key per service GUID with the request URL as subkey (Data, ETag, Expires...).
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/SIH/SLS/\\{[0-9A-Fa-f-]{36}\\}(/[^|]*)?(\\|.*)?$',
     'SIH (Windows Update self-healing client) service-locator cache (approved 2026-11-14).'),
    # WER termination records: TermReason\<pid> keys (CreationTime, Reason, Terminator) written when a process is
    # terminated, plus their container key. Numeric PID names only.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/Windows Error Reporting/TermReason(/[0-9]+)?(\\|.*)?$',
     'Windows Error Reporting per-PID termination records TermReason\\<pid> and their container (approved 2026-11-14).'),
    # 2026-11-15 (gate reviews of r2, f2d, x2). Each family below was seen in null runs (no app involved) on both
    # images, listed with the null runs in the comment; all are under Windows-owned roots and name no app.
    # Census (device inventory task): Census|StartTime/EndTime/RunCounter/ReturnCode. Null runs r0-null3,
    # r2-null2 (Inbound), f0-null3 (Clean-Pro), f1d-null1 (dirty-base).
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Census' + TAIL,
     'Census (device inventory scheduled task) run bookkeeping (null runs, 2026-11-15).'),
    # Appraiser/compat database refresh tick. Null runs r0-null3, r2-null2, f0-null3, f1d-null1.
    ('^[VC]:HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/AppCompatFlags\\|PatchDbUpdateTickCount$',
     'Application-compatibility patch database refresh tick (null runs, 2026-11-15).'),
    # Store install service: AutoUpdateLastSuccessTime. Null runs r0-null3, r2-null2, f1d-null1.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/InstallService/State' + TAIL,
     'Microsoft Store install service state (auto-update timestamps) (null runs, 2026-11-15).'),
    # OneSettings cloud configuration cache: ...\appcompat\runtimesdbincloud|RefreshAfter. Null runs r0-null3,
    # r2-null2, f1d-null1.
    ('^[KVC]:HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/OneSettings' + TAIL,
     'OneSettings cloud-configuration cache refresh state (null runs, 2026-11-15).'),
    # The kernel's list of loaded hives: the COMPONENTS hive is mounted by servicing (CBS). Null runs r0-null3,
    # f0-null3; one of the 11 r2 sanity differences.
    ('^[VC]:HKLM/SYSTEM/CurrentControlSet/Control/hivelist\\|\\\\REGISTRY\\\\MACHINE\\\\COMPONENTS$',
     'hivelist entry of the COMPONENTS hive, loaded by Windows servicing (null runs, 2026-11-15).'),
    # Windows backup of the Start app list (AppListBackup|LastRun, IsBackupEnabledAndMSAAttached). Null run r2-null2.
    ('^[KVC]:' + U + '/Software/Microsoft/Windows/CurrentVersion/AppListBackup' + TAIL,
     'Windows Backup app-list backup bookkeeping (null run, 2026-11-15).'),
    # Delivery Optimization usage counters in the NETWORK SERVICE profile. Every null run of every campaign
    # (21 runs) has some of them; the ambient sets keep exact names only, so a new counter name escaped them.
    ('^[KVC]:HKU/S-1-5-20/Software/Microsoft/Windows/CurrentVersion/DeliveryOptimization' + TAIL,
     'Delivery Optimization (NETWORK SERVICE) usage counters and config (all null runs, 2026-11-15).'),
    # Windows Hello / NGC key-attestation state (LOCAL SERVICE profile and the machine Ngc key). Null runs r0-null3,
    # r2-null2, f0-null3, f0d-null1/2, f1d-null1/2, f2d-null1/2.
    ('^[KVC]:(HKU/S-1-5-19/Software/Microsoft/Cryptography/NGC|HKLM/SYSTEM/CurrentControlSet/Control/Cryptography/Ngc)' + TAIL,
     'Windows Hello (NGC) key attestation state (null runs, 2026-11-15).'),
    # Microsoft-account device-ID cookie (AuthCookies\Live\Default\DIDC|Data), refreshed by the wlidsvc service in
    # every profile. Null runs f0-null1..3, f0d-null2, f2d-null1, r1-null2, r2-null1, r2-null2.
    ('^[KVC]:HKU/S-1-5-[0-9-]+/Software/Microsoft/AuthCookies/Live/Default/DIDC' + TAIL,
     'Microsoft-account device-ID cookie refreshed by wlidsvc (null runs, 2026-11-15).'),
]


def main(d):
    rules = [dict(label='ambient', match=rx(m), why=w) for m, w in OS]
    rules += [dict(label='ambient', match=rx(m), why=w, split=True) for m, w in SPLIT]
    rules += [dict(label='ambient', match=rx(m), why=w) for m, w in OS_VALUES]
    out = dict(id='_os',
               note='Generated by vm/truth/mk_labels.py. Shared OS side effects: state Windows writes during any install, launch '
                    'or uninstall that no uninstaller should remove and no tool can attribute. Included by every app label file. '
                    'Ambient rules run before per-app rules (except `first` rules), so every pattern is anchored under a '
                    'Windows-owned root.',
               rules=rules)
    with open(d + '/_os.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    srv = dict(id='_os-servicing',
               note='Generated by vm/truth/mk_labels.py (SERVICING). M1a gate only: vm/truth/m1a.sh passes it as a second '
                    '--labels file; the M0 recompute (truth/recompute.sh) does not, so the frozen M0 truth is unchanged. '
                    'Windows servicing and telemetry families that run on their own schedule (OS background activity by '
                    'nature). The primary ambient source is the null runs of the same campaign (vm/RIG.md section 6).',
               rules=[dict(label='ambient', match=rx(m), why=w) for m, w in SERVICING])
    with open(d + '/_os-servicing.json', 'w', encoding='utf-8') as f:
        json.dump(srv, f, indent=2, ensure_ascii=False)

    for id in ['npp', '7zip', 'vscode', 'git', 'python', 'node', 'vcredist', 'firefox'] + list(NEW_BASES):
        fn = f'{d}/{id}.json'
        try:
            with open(fn, encoding='utf-8') as f:
                j = json.load(f)
        except FileNotFoundError:
            if id not in NEW_BASES:
                raise
            j = {'id': id, 'rules': NEW_BASES[id]['rules'], 'note': NEW_BASES[id]['note']}
        keep = [r for r in j.get('rules', []) if not r.get('gen')
                and not r.get('why', '').startswith(('Python Launcher (still installed, product', 'The uninstaller removed the'))]
        gen = []
        if id == 'python':
            gen.append(dict(label='kept_owner', gen=True,
                            match=rx(r'^P:C:/Windows/(Installer/SourceHash\{73831AC2-F0E1-4173-9FDB-D07463D7EB80\}|pyshellext\.amd64\.dll)$'),
                            why='Python Launcher (still installed, product {73831AC2...}): its MSI source hash and the shell extension behind CLSID {BEA218D2...}.'))
        for h, appid in JUMP.get(id, {}).items():
            gen.append(dict(label='leftover', first=True, gen=True, match=rx(AD + h + r'\.automaticDestinations-ms$'),
                            why=f'Jump list of AppID {appid} (CRC-64 {h}); FS-JUMPLISTS, Unchecked.'))
        if id in PREFETCH:
            names = '|'.join(PREFETCH[id])
            gen.append(dict(label='leftover', first=True, gen=True,
                            match=rx(r'^P:C:/Windows/Prefetch/(' + names + r')\.EXE-[0-9A-F]{8}\.pf$'),
                            why='Prefetch trace of the app\'s own executable (FS-PREFETCH: unique exe name and path hash).'))
        j2 = {'id': j['id'], 'include': ['_os.json'], 'rules': gen + keep}
        for k, v in j.items():
            if k not in ('id', 'include', 'rules'):
                j2[k] = v
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(j2, f, indent=2, ensure_ascii=False)

    for id, v in VARIANTS.items():
        fn = f'{d}/{id}.json'
        try:
            with open(fn, encoding='utf-8') as f:
                j = json.load(f)
        except FileNotFoundError:
            j = {'id': id, 'rules': []}
        keep = [r for r in j.get('rules', []) if not r.get('gen')]
        gen = [dict(r, gen=True) for r in v.get('rules', [])]
        # `_os.json` first (as in every app file), then the base app's file, which includes `_os.json` again:
        # the duplicate rules are harmless, a rule's label decides its precedence, not its position.
        j2 = {'id': id, 'include': ['_os.json', v['base'] + '.json'], 'note': v['note'], 'rules': gen + keep}
        for k, val in j.items():
            if k not in ('id', 'include', 'note', 'rules'):
                j2[k] = val
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(j2, f, indent=2, ensure_ascii=False)
    print(f'_os.json: {len(rules)} rules ({len(SPLIT)} split); _os-servicing.json: {len(SERVICING)} rules; '
          f'variants: {", ".join(VARIANTS)}')


if __name__ == '__main__':
    main(sys.argv[1])
