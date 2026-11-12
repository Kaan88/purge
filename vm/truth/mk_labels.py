"""Generates vm/truth/labels/_os.json and the generated rules of the per-app label files.

    python -I vm/truth/mk_labels.py vm/truth/labels

_os.json holds the shared OS side effects (label `ambient`). Each app file keeps its hand-written rules;
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
}

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
                'danger by the scorer\'s own rule; no kept_owner rule is needed for it. Freeze after review of the first '
                'r0-firefox-tb run.',
    },
}


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

    for id in ['npp', '7zip', 'vscode', 'git', 'python', 'node', 'vcredist', 'firefox']:
        fn = f'{d}/{id}.json'
        with open(fn, encoding='utf-8') as f:
            j = json.load(f)
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
        # `_os.json` first (as in every app file), then the base app's file, which includes `_os.json` again:
        # the duplicate rules are harmless, a rule's label decides its precedence, not its position.
        j2 = {'id': id, 'include': ['_os.json', v['base'] + '.json'], 'note': v['note'], 'rules': keep}
        for k, val in j.items():
            if k not in ('id', 'include', 'note', 'rules'):
                j2[k] = val
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(j2, f, indent=2, ensure_ascii=False)
    print(f'_os.json: {len(rules)} rules ({len(SPLIT)} split); variants: {", ".join(VARIANTS)}')


if __name__ == '__main__':
    main(sys.argv[1])
