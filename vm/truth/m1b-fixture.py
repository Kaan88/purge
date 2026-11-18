"""Evidence for the m1b.sh selftest (review R4b): a SYNTHETIC evidence dir that passes the M1b scan gate in its default
configuration, and the bad-run mutations that must make it fail. Not a VM capture; numbers are illustrative only.

    python -I m1b-fixture.py write <dir> <vm/truth dir>   the passing evidence dir; <dir>/truth/ holds a copy of the
                                                          committed trap file and label files and a fixture frozen truth
                                                          of powershell and temurin
    python -I m1b-fixture.py labelmap                     the "run=label-id ..." map collect would write
    python -I m1b-fixture.py mutate <dir> <name>          one bad-run control (names: MUTATIONS below)
    python -I m1b-fixture.py nullmap                      the null runs collect would hand to the manifest
    python -I m1b-fixture.py replayruns <dir> [<skip id>] five fake frozen runs for `m1b.sh replay` (review R4c S2)
    python -I m1b-fixture.py xtask <vm/truth> <args...>   stub of `cargo xtask replay-diff | replay` for that step
    python -I m1b-fixture.py rigtool <args...>            stub of `rigtool score` for that step
    python -I m1b-fixture.py git <args...>                stub of git for that step (HEAD = COMMIT, clean)

The manifest is written by m1b.sh itself (pyeval manifest), as collect writes it. The replay diff is the committed
vm/truth/m1b-replay-diff.json, so the selftest fails when the scorer and the committed diff disagree (R4b B1).
"""
import hashlib
import json
import os
import re
import shutil
import sys

SID = 'S-1-5-21-1000000000-2000000000-3000000000-1001'
APPS = ['7zip', 'python', 'python312-with-313', 'python313-with-312', 'node', 'vcredist', 'powershell', 'temurin']
DIRTY_APPS = [a for a in APPS if a != 'node']   # G3 without node (ruling 2026-11-18: dirty-base has Node.js 20.18.0)
CP_APPS = ['7zip', 'python', 'vcredist']
PREFIX = {'clean': 'm1b', 'dirty': 'm1bd', 'cp': 'm1bcp'}
TRAP_RUNS = ['m1b-traps-7zip', 'm1bd-traps-7zip', 'm1bcp-traps-7zip']
ENGINE = 'e' * 64
COMMIT = 'c' * 40
REPLAY_IDS = ['vscode', 'git', 'firefox', 'npp', '7zip']
# fixture frozen truths (FROZEN, SANITY of the six apps that have one, replay)
FROZEN_IDS = ['powershell', 'temurin', '7zip', 'python', 'node', 'vcredist'] + REPLAY_IDS[:4]
NULL_RUNS = [f'{PREFIX[s]}-null{n}' for s in ('clean', 'dirty', 'cp') for n in (1, 2, 3)]


def wj(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


def rj(path):
    with open(path, encoding='utf-8-sig') as f:
        return json.load(f)


def set_apps(s):
    return {'cp': CP_APPS, 'dirty': DIRTY_APPS}.get(s, APPS)


def app_runs():
    return [(s, a, f'{PREFIX[s]}-{a}') for s in ('clean', 'dirty', 'cp') for a in set_apps(s)]


def item(target, band='Safe', pre=None, outcome='hit'):
    return {'target': target, 'band': band, 'preselected': band == 'Safe' if pre is None else pre, 'outcome': outcome}


# The bam value REF-ANY lists Blocked (DenyListed reg.hklm.system) in the real python and vcredist runs: a danger
# item kept, not offered (ruling 2026-11-18, K1 / K8 count danger_offered).
BAM = (f'V:HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{SID}|\\Device\\HarddiskVolume4\\'
       'ProgramData\\Package Cache\\{d8bbe9f9-7c5b-42c6-b715-9ee898a2e515}\\VC_redist.x64.exe')
KEPT_DANGER = {'python', 'vcredist'}


def danger_item(band='Blocked'):
    return {'target': BAM, 'band': band, 'preselected': band == 'Safe', 'scanner': 'REF-ANY', 'action': 'DeleteValue',
            'outcome': 'danger', 'class': 'unticked' if band != 'Safe' else 'blocking'}


def scan_item(target, action, band, blockers=(), suggest=None):
    """A scan sidecar item (purge.scan/0 shape: target, action, blockers, evidence, decision)."""
    det = {'what': 'related_product', 'suggest_uninstall': suggest} if suggest else {'token': 'fixture'}
    return {'target': target, 'action': action, 'scanner': 'SYS-BURNDEPS' if suggest else 'REF-ANY',
            'blockers': [dict(b) for b in blockers], 'evidence': [{'kind': 'HarvestedToken', 'detail': det}],
            'decision': {'band': band, 'preselected': band == 'Safe'}}


# The engine writes ControlSet001 where the score (and BAM above) says CurrentControlSet: K1 matches them (review R5 S3).
BAM_SCAN = {'type': 'RegValue', 'path': BAM[2:].split('|', 1)[0].replace('CurrentControlSet', 'ControlSet001'),
            'name': BAM.split('|', 1)[1]}
DENY = {'kind': 'DenyListed', 'rule': 'reg.hklm.system'}


def bam_scan_item(band='Blocked', blockers=(DENY,)):
    return scan_item(BAM_SCAN, 'DeleteValue', band, blockers if band == 'Blocked' else ())


# The Python Launcher (review R5 B1, B2): orphaned on rig-base and Clean-Pro (3.12.7's, suggested), kept by
# dirty-base's Python 3.13.1 (its own Launcher, Protected, no suggestion).
UNINST = 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
LAUNCHER_KEY = UNINST + '{73831AC2-F0E1-4173-9FDB-D07463D7EB80}'
LAUNCHER_313_KEY = UNINST + '{7102CAE5-270C-4E81-AC25-27699156D8AE}'
LAUNCHER_NAME = 'Python Launcher (64-bit)'


def suggestion_item(key=LAUNCHER_KEY, action='ReportOnly'):
    return scan_item({'type': 'RegKey', 'path': key}, action, 'Likely', suggest=LAUNCHER_NAME)


def notice(key=LAUNCHER_KEY):
    return {'target': 'K:' + key, 'band': 'Likely', 'preselected': False, 'scanner': 'SYS-BURNDEPS', 'action': 'ReportOnly',
            'suggest_uninstall': LAUNCHER_NAME, 'would_be': 'danger', 'truth': ['kept_owner K:' + key]}


OTHER = {'kind': 'OtherApps', 'rule': 'Python 3.13.1'}


def launcher_kept_items():
    """dirty-base: the 3.13.1 Launcher's objects the scanners find, all Blocked (kept: another dependent remains)."""
    return [scan_item({'type': 'Path', 'path': 'C:\\Windows\\py.exe'}, 'Quarantine', 'Blocked', (OTHER,)),
            scan_item({'type': 'RegKey', 'path': LAUNCHER_313_KEY}, 'DeleteKey', 'Blocked', (OTHER,))]


def scan_doc(s, app):
    items = []
    if app in KEPT_DANGER:
        items.append(bam_scan_item())
    if app == 'python' and s in ('clean', 'cp'):
        items.append(suggestion_item())
    if app == 'python' and s == 'dirty':
        items += launcher_kept_items()
    return {'schema': 'purge.scan/0', 'app': app, 'items': items}


def set_danger(t, items):
    """Puts the danger items into a purge score as rigtool score counts them."""
    t['items'] = [i for i in t['items'] if i.get('outcome') != 'danger'] + items
    t['danger'] = [dict(i) for i in items]
    t['danger_listed'] = len(items)
    t['danger_kept'] = sum(1 for i in items if i['band'] == 'Blocked')
    t['danger_offered'] = t['danger_listed'] - t['danger_kept']
    t['danger_blocking'] = sum(1 for i in items if i['band'] == 'Safe' or i['preselected'])
    t['danger_preselected'] = sum(1 for i in items if i['preselected'])
    t['offered_n'] = len(t['items'])


def tool(app):
    items = {
        '7zip': [item('D:C:\\Program Files\\7-Zip'), item(f'K:HKU\\{SID}\\Software\\7-Zip')],
        'python': [item(f'D:C:\\Users\\rig\\AppData\\Local\\Programs\\Python\\Python312')],
        'python312-with-313': [item('D:C:\\Program Files\\Python312')],
        'python313-with-312': [item('D:C:\\Program Files\\Python313')],
        'node': [item('D:C:\\Program Files\\nodejs')],
        'vcredist': [item('K:HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC', 'Likely')],
        'powershell': [item('D:C:\\Program Files\\PowerShell\\7')],
        'temurin': [item('D:C:\\Program Files\\Eclipse Adoptium')],
    }[app]
    pn = 30 if app in ('python312-with-313', 'python313-with-312') else 0
    t = {'tool': 'purge', 'truth_n': 3, 'offered_n': len(items), 'danger_listed': 0, 'danger_offered': 0, 'danger_kept': 0,
         'danger_blocking': 0, 'danger_preselected': 0, 'userdata_preselected': 0, 'danger': [],
         'precision_safe': 1.0 if any(i['band'] == 'Safe' for i in items) else None,
         'protected_n': pn, 'protected_correct': 1.0 if pn else None, 'protected_wrong': [], 'items': items,
         'notices': []}
    if app in KEPT_DANGER:
        set_danger(t, [danger_item('Blocked')])
    return t


def hku(path):
    if path.upper().startswith('HKCU\\SOFTWARE\\CLASSES\\'):
        return f'HKU\\{SID}_Classes\\' + path[len('HKCU\\Software\\Classes\\'):]
    if path.upper().startswith('HKCU\\'):
        return f'HKU\\{SID}\\' + path[5:]
    return path


def planted_entry(t):
    ty = t['type']
    if ty == 'Service':
        return {'kind': 'service', 'target': 'SVC:' + t['name'], 'note': 'ImagePath=fixture'}
    if ty == 'Task':
        return {'kind': 'task', 'target': 'TASK:' + t['path'], 'note': ''}
    if ty == 'FirewallRule':
        return {'kind': 'firewall', 'target': 'FW:' + t['id'], 'note': ''}
    if ty == 'RegKey':
        return {'kind': 'value', 'target': 'V:' + hku(t['path']) + '|', 'note': 'fixture'}
    if ty == 'RegValue':
        return {'kind': 'value', 'target': 'V:' + hku(t['path']) + '|' + t['name'], 'note': 'fixture'}
    if ty == 'Path':
        return {'kind': 'file', 'target': 'P:' + t['path'], 'note': ''}
    raise SystemExit(f'fixture: unknown target type {ty}')


def planted_doc(traps):
    cases = {}
    for c in traps['cases']:
        cases[c['id']] = {'id': c['id'], 'phase': c['phase'], 'plant': c['plant'], 'at': '2026-11-17T10:00:00+01:00',
                          'ok': True, 'skipped': False, 'error': None,
                          'planted': [planted_entry(e['target']) for e in c['expect']]}
    cases['com-shared-class#between'] = {
        'id': 'com-shared-class', 'phase': 'between', 'plant': 'Repoint-SharedComClass', 'at': '2026-11-17T10:05:00+01:00',
        'ok': True, 'skipped': False, 'error': None,
        'planted': [{'kind': 'value', 'target': 'V:HKLM\\SOFTWARE\\Classes\\CLSID\\{AA0252AF-8AAD-4AAB-9CF2-50CFE0FD31DF}\\InprocServer32|',
                     'note': 'C:\\Program Files\\nodejs\\PurgeTrapShared.dll'}]}
    return {'schema': 'purge.rig.m1b-traps.planted/1', 'computer': 'INBOUND-WIN11-T', 'trap_a': '7zip', 'trap_b': 'node',
            'updated': '2026-11-17T10:30:00+01:00', 'cases': cases}


# The Defender record runsum keeps of run.json `defender` (ruling 2026-11-18, RIG.md section 12.7): versions at snap 0
# and snap 2 equal, the idle wait stable.
DEF_V = {'av_signature': '1.465.100.0', 'as_signature': '1.465.100.0', 'engine': '1.1.25100.9', 'platform': '4.18.25100.9',
         'source': 'MSFT_MpComputerStatus', 'error': None}


def defender_doc():
    return {'snap0': dict(DEF_V), 'snap2': dict(DEF_V),
            'idle': {'stable': True, 'bounded': False, 'updated': True, 'changes': 1, 'waited_sec': 75.2, 'error': None,
                     'trigger_exit': 0, 'trigger_timed_out': False, 'trigger_error': None, 'current': True,
                     'attempts': [{'exit': 0, 'sec': 14.1, 'timed_out': False}]}}


def run_doc(run, phases, inputs):
    sha = hashlib.sha256(('run.json of ' + run).encode()).hexdigest()
    key = f'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Fixture-{run}'
    return {'schema': 'purge.rig.m1b-run/1', 'run': run, 'run_json_sha256': sha,
            # the target ARP entry (ruling 2026-11-18): new in this run; null runs have none
            'target': None if inputs is None else {'main_key': key, 'main_name': 'Fixture ' + run, 'main_msi': None,
                                                   'entries_created': [key], 'in_lists0': False, 'main_created': True,
                                                   'main_is_pre': False, 'pre_keys': [NODE_KEY] if 'traps' in run else []},
            'run_json': {'run': run, 'started': '2026-11-17T09:00:00+01:00', 'finished': '2026-11-17T09:40:00+01:00',
                         'phases': [{'name': p, 'ok': True, 'error': None} for p in phases], 'defender': defender_doc()},
            'build': None if inputs is None else {
                'schema': 'purge.rig.m1b-build/1', 'run': run, 'run_json_sha256': sha, 'engine': 'purge-engine.exe',
                'engine_sha256': ENGINE, 'engine_sha256_after': ENGINE, 'commit': COMMIT, 'source_dirty': False,
                'inputs': dict(inputs), 'inputs_after': dict(inputs), 'inputs_dirty': False},
            'plan_items': 2}


def sha_file(p):
    with open(p, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def rig_inputs(truth):
    """The rig input hashes rig.ps1 (Get-M1bRigInputs) would record for the fixture's truth copy (review R4c S3)."""
    out = {'vm/truth/m1b-traps.json': sha_file(os.path.join(truth, 'm1b-traps.json')),
           'vm/truth/deny.json': sha_file(os.path.join(truth, 'deny.json')),   # review R4d S1
           'vm/rig.ps1': 'a' * 64, 'vm/guest/m1b-traps.ps1': 'b' * 64, 'vm/guest/run-app.ps1': 'd' * 64}
    for f in sorted(os.listdir(os.path.join(truth, 'labels'))):
        if f.endswith('.json'):
            out['vm/truth/labels/' + f] = sha_file(os.path.join(truth, 'labels', f))
    fz = os.path.join(truth, 'frozen')   # review R4d S1: every file under truth/frozen
    for root, _, files in os.walk(fz):
        for f in files:
            out['vm/truth/frozen/' + os.path.relpath(os.path.join(root, f), fz).replace(os.sep, '/')] = sha_file(os.path.join(root, f))
    return out


TEMP = 'C:\\Users\\tester\\AppData\\Local\\Temp'


def frozen_truth(a):
    """A fixture frozen truth: one leftover, one ambient item; python also the bundle's random-named temp leftover
    (the real frozen python truth has DEL3917.tmp; review R4d S2)."""
    items = [
        {'target': {'type': 'RegKey', 'path': f'HKLM\\SOFTWARE\\Fixture\\{a}'}, 'label': 'leftover', 'rule': 'default'},
        {'target': {'type': 'Path', 'path': 'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\x.etl'}, 'label': 'ambient', 'rule': 'ambient:exact'}]
    if a == 'python':
        items.append({'target': {'type': 'Path', 'path': TEMP + '\\DEL3917.tmp'}, 'label': 'leftover', 'rule': 'default'})
    return {'schema': 'fixture', 'id': a, 'items': items}


APP_PHASES = ['setup', 'defender-idle', 'install', 'launch', 'lists1', 'engine-inventory-1', 'snap1', 'msi-tables-1', 'engine-harvest',
              'uninstall', 'lists2', 'engine-inventory-2', 'snap2', 'msi-tables-2', 'edge-check', 'entries', 'engine-scan']
TRAP_PHASES = ['setup', 'pre-node', 'defender-idle', 'install', 'launch', 'm1b-traps-pre', 'lists1', 'snap1', 'msi-tables-1', 'engine-harvest',
               'm1b-traps-between', 'uninstall', 'm1b-traps-post', 'lists2', 'snap2', 'msi-tables-2', 'engine-scan']


def budget_log(engine, step, kind):
    total = {('m1b', 'harvest'): 9.0, ('m2', 'harvest'): 7.5, ('m1b', 'scan'): 8.0, ('m2', 'scan'): 6.5}[(engine, step)]
    if kind in ('cold', 'cold-warm'):
        total += 3.0
    lines = ['[  0.010s] purge-engine ' + step]
    # ruling 2026-11-18: the M1b engine's MSI table cache on disk (cold: all misses; warm: hits, no table read)
    # 'cold-warm': a cold scan run right after the cold harvest without moving the cache aside again (the rig before
    # review R5 B3): every package a cache hit, no table read
    reads = 313 if engine == 'm2' or kind == 'cold' else 0
    if engine == 'm1b':
        if step == 'scan':
            lines.append('timing: phase refscan 1.200s')
        lines.append('timing: phase ownership.components 0.800s')
        lines.append('timing: phase ownership.tables %.3fs; fs.metadata 313 0.012s%s' % (
            2.5 if kind == 'cold' else 0.1, f'; sys.msi_tables {reads}/140094 3.180s' if reads else ''))
        lines.append('timing: msi_table_cache disk C:\\ProgramData\\Purge\\fp\\msitables hits=%d misses=%d'
                     % ((0, 313) if kind == 'cold' else (313, 0)))
    if step == 'harvest':
        # G7 like for like: both engines find the program's install root, no co-product
        lines.append('harvest: Fixture MSI App 1.0 (HKLM|64|{F1X}); 1 root(s), 0 rejected; no Inno log; '
                     '0 co-product candidate(s); reference snapshot incomplete')
    lines.append('timing: total: reg.key_info 756813 12.750s; fs.metadata 505 0.016s%s; sys.tasks 1/276 0.242s'
                 % (f'; sys.msi_tables {reads}/140094 3.180s' if reads else ''))
    lines.append('[%7.3fs] done' % total)
    return '\n'.join(lines) + '\n'


def write(d, here):
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)
    # committed inputs (copies) and the fixture frozen truth
    os.makedirs(os.path.join(d, 'truth', 'labels'))
    shutil.copy(os.path.join(here, 'm1b-traps.json'), os.path.join(d, 'truth', 'm1b-traps.json'))
    for f in os.listdir(os.path.join(here, 'labels')):
        if f.endswith('.json'):
            shutil.copy(os.path.join(here, 'labels', f), os.path.join(d, 'truth', 'labels', f))
    shutil.copy(os.path.join(here, 'deny.json'), os.path.join(d, 'truth', 'deny.json'))
    for a in FROZEN_IDS:
        wj(os.path.join(d, 'truth', 'frozen', a, 'truth.json'), frozen_truth(a))
    # the rig-base run truths SANITY compares with the frozen ones (review R4c S4)
    for a in FROZEN_IDS:
        if a in APPS:
            wj(os.path.join(d, f'truth-clean-{a}.json'), frozen_truth(a))
    inputs = rig_inputs(os.path.join(d, 'truth'))
    # scores
    for s in ('clean', 'dirty', 'cp'):
        apps = []
        for a in set_apps(s):
            t = tool(a)
            if a == 'python' and s in ('clean', 'cp'):
                t['notices'] = [notice()]   # rigtool score: the suggestion is a notice, not an item (review R5 B1)
            apps.append({'id': a, 'dir': f'runs/{PREFIX[s]}-{a}', 'tools': [t]})
            wj(os.path.join(d, f'{s}-{a}-scan.json'), scan_doc(s, a))
        wj(os.path.join(d, f'score-{s}.json'), {'apps': apps})
    wj(os.path.join(d, 'clean-7zip-fp.json'), {'roots': [{'path': 'C:\\Program Files\\7-Zip', 'source': 'MsiComponent'}]})
    # replay (G1): the committed diff, then the score whose replay block binds it (review R4d S3)
    shutil.copy(os.path.join(here, 'm1b-replay-diff.json'), os.path.join(d, 'replay-diff.json'))
    wj(os.path.join(d, 'replay-score.json'), {'apps': [
        {'id': a, 'tools': [{'tool': 'purge', 'danger_listed': 0, 'precision_safe': 1.0, 'truth_n': 3, 'offered_n': 1,
                             'items': [item(f'K:HKU\\{SID}\\Software\\7-Zip' if a == '7zip' else f'K:HKLM\\SOFTWARE\\Fixture\\{a}')]}]}
        for a in REPLAY_IDS], 'replay': replay_block(os.path.join(d, 'truth'), os.path.join(d, 'replay-diff.json'))})
    # traps
    traps = rj(os.path.join(here, 'm1b-traps.json'))
    for run in TRAP_RUNS:
        wj(os.path.join(d, f'traps-{run}.json'), {'summary': {'cases': 26, 'expectations': 44, 'met': 44, 'escapes': 0, 'missed_owned': 0}})
        wj(os.path.join(d, f'traps-planted-{run}.json'), planted_doc(traps))
    # run records
    for _, _, run in app_runs():
        wj(os.path.join(d, 'runs', f'{run}.json'), run_doc(run, APP_PHASES, inputs))
    for run in TRAP_RUNS:
        wj(os.path.join(d, 'runs', f'{run}.json'), run_doc(run, TRAP_PHASES, inputs))
    for run in NULL_RUNS:
        wj(os.path.join(d, 'runs', f'{run}.json'), run_doc(run, ['setup', 'defender-idle', 'snap0', 'wait', 'snap1', 'snap2'], None))
    # budgets (G7)
    runs = []
    os.makedirs(os.path.join(d, 'budgets'), exist_ok=True)
    # coordinator ruling 2026-11-18 (gate5): 5 rounds, the engines alternating within each round (rig.ps1)
    for n in (1, 2, 3, 4, 5):
        kind = 'cold' if n == 1 else 'warm'
        for e in (('m1b', 'm2') if n % 2 else ('m2', 'm1b')):
            for step in ('harvest', 'scan'):
                log = f'{e}-{step}-{n}.log'
                with open(os.path.join(d, 'budgets', log), 'w', encoding='utf-8') as f:
                    f.write(budget_log(e, step, kind))
                runs.append({'engine': e, 'step': step, 'round': n, 'kind': kind, 'seq': len(runs) + 1, 'log': log, 'exit': 0,
                             'wall_s': 5.0, 'host_cpu_percent': 6.5})
    wj(os.path.join(d, 'budgets', 'budgets.json'),
       {'schema': 'purge.rig.m1b-budgets/4', 'program': 'fixture-program', 'host': 'FIXTURE', 'engines': {'m1b': 'm1b.exe', 'm2': 'm2.exe'},
        'engine_sha256': {'m1b': ENGINE, 'm2': 'f' * 64}, 'rounds': 5, 'logical_cpus': 8,
        'settle': {'settled': True, 'waited_sec': 212.4, 'cpu_percent': 2.1, 'cpu_window_sec': 30, 'quiet_sec': 180,
                   'max_cpu_percent': 10, 'vm_processes_seen': []},
        'power_plan': {'guid': '381b4222-f694-41f0-9685-ff5bb260df2e', 'text': 'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)'},
        'cold_cache_state': 'moved',
        'cold_cache': {'harvest': 'msitables.aside-harvest', 'scan': 'msitables.aside-scan'},
        'cold_cache_steps': {'harvest': 'moved', 'scan': 'moved'}, 'runs': runs})


def labelmap():
    return ' '.join(f'{run}={a}' for _, a, run in app_runs())


def replay_block(truth, diff):
    """The block `m1b.sh replay` (pyeval replaybind) adds to the replay score."""
    return {'schema': 'purge.rig.m1b-replay/1', 'runs': list(REPLAY_IDS), 'commit': COMMIT, 'source_dirty': False,
            'diff_sha256': sha_file(diff), 'diff_exit': 0,
            'frozen': {a: sha_file(os.path.join(truth, 'frozen', a, 'truth.json')) for a in REPLAY_IDS}}


# ------------------------------------------------------------------------------------------- mutations
def edit(d, name, fn):
    p = os.path.join(d, name)
    doc = rj(p)
    fn(doc)
    wj(p, doc)


def app_tool(doc, app):
    return next(a for a in doc['apps'] if a['id'] == app)['tools'][0]


PROMO = {'app': 'git', 'target': {'type': 'RegKey', 'path': 'HKLM\\SOFTWARE\\GitForWindows'},
         'before': {'target': {'type': 'RegKey', 'path': 'HKLM\\SOFTWARE\\GitForWindows'}, 'band': 'Likely', 'preselected': False,
                    'scanner': 'REG-SOFTWARE', 'absorbed': False, 'blockers': []},
         'after': {'target': {'type': 'RegKey', 'path': 'HKLM\\SOFTWARE\\GitForWindows'}, 'band': 'Safe', 'preselected': True,
                   'scanner': 'REG-SOFTWARE', 'absorbed': False, 'blockers': []}}


def add_row(reason, listed=False, demote=False):
    def fn(doc):
        r = json.loads(json.dumps(PROMO))
        if demote:
            r['before'], r['after'] = r['after'], r['before']
        r['reason'] = reason
        doc['rows'].append(r)
        if not demote:
            doc['promotions'] = doc.get('promotions', 0) + 1
        if listed:
            doc.setdefault('justified_promotions', []).append({'app': 'git', 'target': PROMO['target'], 'cause': 'fixture cause'})
    return fn


def planted_case(d, run, fn):
    edit(d, f'traps-planted-{run}.json', lambda doc: fn(doc['cases']))


def build(run, fn):
    return lambda d: edit(d, f'runs/{run}.json', lambda doc: fn(doc['build']))


def all_builds(fn):
    def go(d):
        for f in os.listdir(os.path.join(d, 'runs')):
            doc = rj(os.path.join(d, 'runs', f))
            if doc.get('build'):
                fn(doc['build'])
                wj(os.path.join(d, 'runs', f), doc)
    return go


def set_input(key, val, after_only=False):
    def fn(b):
        if not after_only:
            b['inputs'][key] = val
        b['inputs_after'][key] = val
    return fn


def relabel(label):
    return lambda doc: doc['items'][0].update(label=label)


def budget_runs(fn):
    return lambda d: edit(d, 'budgets/budgets.json', fn)


def append_ws(rel):
    def fn(d):
        with open(os.path.join(d, rel), 'a', encoding='utf-8') as f:
            f.write('\n')
    return fn


def drop_svchost_value(cases, note_only=False):
    c = cases['svc-svchost']
    if note_only:
        for p in c['planted']:
            if 'Svchost|PurgeTrapGroup' in p['target']:
                p['kind'] = 'note'
                p['note'] = 'not written: access denied'
    else:
        c['planted'] = [p for p in c['planted'] if 'Svchost|PurgeTrapGroup' not in p['target']]


def edit_diff(fn):
    """Edits the replay diff and binds the replay score to the edited file (as `m1b.sh replay` would have written
    both), so a K16 control tests K16 and not the R4d S3 binding."""
    def go(d):
        edit(d, 'replay-diff.json', fn)
        edit(d, 'replay-score.json', lambda doc: doc['replay'].update(diff_sha256=sha_file(os.path.join(d, 'replay-diff.json'))))
    return go


def score_danger(s, app, *bands):
    """Danger items in the score, and the engine's own record of them in the scan sidecar (a Blocked one deny-listed)."""
    def go(d):
        edit(d, f'score-{s}.json', lambda doc: set_danger(app_tool(doc, app), [danger_item(b) for b in bands]))
        edit(d, f'{s}-{app}-scan.json', lambda doc: doc.update(items=[i for i in doc['items'] if i['target'] != BAM_SCAN]
                                                                + [bam_scan_item(b) for b in bands]))
    return go


def scan_edit(s, app, fn):
    return lambda d: edit(d, f'{s}-{app}-scan.json', lambda doc: doc.update(items=fn(doc['items'])))


def bam_blockers(*blockers):
    def fn(items):
        for i in items:
            if i['target'] == BAM_SCAN:
                i['blockers'] = [dict(b) for b in blockers]
        return items
    return fn


# Review R5b N1: a Blocked danger value in a user hive, the score target spelled with score_hive, and its scan items
# (hive, blockers), one per entry; blockers are never merged across scan items or users' hives.
SID2 = 'S-1-5-21-1000000000-2000000000-3000000000-1002'
USER_DANGER_KEY = 'Software\\FixtureShared'
TOO_LARGE = {'kind': 'TooLarge'}


def user_danger(score_hive, *scan_items):
    def go(d):
        tgt = f'V:{score_hive}\\{USER_DANGER_KEY}|v'
        edit(d, 'score-clean.json', lambda doc: set_danger(app_tool(doc, '7zip'), [dict(danger_item('Blocked'), target=tgt)]))
        edit(d, 'clean-7zip-scan.json', lambda doc: doc['items'].extend(
            scan_item({'type': 'RegValue', 'path': f'{h}\\{USER_DANGER_KEY}', 'name': 'v'}, 'DeleteValue', 'Blocked', bl)
            for h, bl in scan_items))
    return go


# Review R5b S1: notices on the Launcher's Uninstall key only (clean/cp python), none anywhere else.
NOT_LAUNCHER_KEY = UNINST + '{11111111-2222-3333-4444-555555555555}'


def python_suggestions(s, *keys):
    """The python run of set s suggests uninstalling the Launcher on each key: the scan items and the score's notices."""
    def go(d):
        scan_edit(s, 'python', lambda items: [i for i in items if i.get('scanner') != 'SYS-BURNDEPS']
                  + [suggestion_item(k) for k in keys])(d)
        edit(d, f'score-{s}.json', lambda doc: app_tool(doc, 'python').update(notices=[notice(k) for k in keys]))
    return go


def kept_cold_scan(d):
    with open(os.path.join(d, 'budgets', 'm1b-scan-1.log'), 'w', encoding='utf-8') as f:
        f.write(budget_log('m1b', 'scan', 'cold-warm'))


def target(run, **kw):
    return lambda d: edit(d, f'runs/{run}.json', lambda doc: doc['target'].update(**kw))


def defender(run, end, **kw):
    """Changes run.json `defender` <end> (snap0, snap2) of a run record; with no keyword, drops that end's record."""
    def fn(doc):
        dd = doc['run_json']['defender']
        if kw:
            dd[end].update(**kw)
        else:
            dd[end] = None
    return lambda d: edit(d, f'runs/{run}.json', fn)


def run_truth(app, fn):
    return lambda d: edit(d, f'truth-clean-{app}.json', lambda doc: doc.update(items=fn(doc['items'])))


def temp_items(*named):
    """The python run truth with the frozen DEL3917.tmp replaced by (name, label) items of the same normalised name."""
    def fn(items):
        return [i for i in items if 'DEL3917' not in str(i['target'].get('path'))] + [
            {'target': {'type': 'Path', 'path': f'{TEMP}\\{n}'}, 'label': lab, 'rule': 'x'} for n, lab in named]
    return fn


def log_sub(name, old, new):
    """Edits one budget log (regex, at least one hit)."""
    def go(d):
        p = os.path.join(d, 'budgets', name)
        with open(p, encoding='utf-8') as f:
            text = f.read()
        out, n = re.subn(old, new, text, flags=re.M)
        if not n:
            raise SystemExit(f'log_sub: {old!r} not in {name}')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(out)
    return go


def all_of(*fns):
    def go(d):
        for f in fns:
            f(d)
    return go


MUTATIONS = {
    'replay_committed_diff': lambda d: None,
    'replay_promotion_unexplained': edit_diff(add_row('new_scanner')),
    'replay_justified_not_listed': edit_diff(add_row('promotion_justified')),
    'replay_justified_listed': edit_diff(add_row('promotion_justified', listed=True)),
    'replay_justified_no_promotion': edit_diff(add_row('promotion_justified', listed=True, demote=True)),
    'replay_sixth_reason': edit_diff(lambda doc: doc['reasons'].append('looks_fine')),
    'replay_run_missing': edit_diff(lambda doc: doc['apps'].pop('7zip')),
    'replay_old_schema': edit_diff(lambda doc: doc.update(schema='purge.replay-diff/2')),
    'k6_leftover_weak': lambda d: edit(d, 'score-clean.json', lambda doc: (
        app_tool(doc, 'node')['items'].append(item('P:C:\\Users\\rig\\AppData\\Local\\Temp\\node-x.log', 'Weak')),
        app_tool(doc, 'node').update(offered_n=2))),
    'k6_preselected_likely': lambda d: edit(d, 'score-clean.json', lambda doc: app_tool(doc, '7zip')['items'][1].update(band='Likely', preselected=True)),
    'k6_unknown_band': lambda d: edit(d, 'score-dirty.json', lambda doc: app_tool(doc, 'temurin')['items'][0].update(band='Maybe')),
    'plant_missing_target': lambda d: planted_case(d, 'm1b-traps-7zip', drop_svchost_value),
    'plant_note_only': lambda d: planted_case(d, 'm1bd-traps-7zip', lambda c: drop_svchost_value(c, note_only=True)),
    'plant_case_failed': lambda d: planted_case(d, 'm1bcp-traps-7zip', lambda c: c['tracing'].update(ok=False, error='access denied')),
    'plant_between_failed': lambda d: planted_case(d, 'm1b-traps-7zip', lambda c: c.pop('com-shared-class#between')),
    'plant_record_missing': lambda d: os.remove(os.path.join(d, 'traps-planted-m1bd-traps-7zip.json')),
    'plant_wrong_trap_b': lambda d: edit(d, 'traps-planted-m1b-traps-7zip.json', lambda doc: doc.update(trap_b='vlc')),
    'plant_preexisting': lambda d: planted_case(d, 'm1bd-traps-7zip', lambda c: c['com-isimpledom']['planted'][0].update(
        kind='key', note='existed, kept (registered by another product: {0000})')),
    'empty_plan': lambda d: edit(d, 'score-clean.json', lambda doc: app_tool(doc, 'node').update(items=[], offered_n=0, precision_safe=None)),
    'empty_plan_dirty': lambda d: edit(d, 'score-dirty.json', lambda doc: app_tool(doc, 'temurin').update(items=[], offered_n=0, precision_safe=None)),
    'score_without_counts': lambda d: edit(d, 'score-cp.json', lambda doc: app_tool(doc, 'python').pop('truth_n')),
    'run_phase_failed': lambda d: edit(d, 'runs/m1b-traps-7zip.json', lambda doc: next(p for p in doc['run_json']['phases'] if p['name'] == 'm1b-traps-pre').update(ok=False, error='a case failed')),
    'run_unfinished': lambda d: edit(d, 'runs/m1bcp-python.json', lambda doc: doc['run_json'].update(finished=None)),
    'run_json_missing': lambda d: os.remove(os.path.join(d, 'runs', 'm1bd-temurin.json')),
    'unbound_engine': build('m1bcp-7zip', lambda b: b.update(engine_sha256='a' * 64, engine_sha256_after='a' * 64)),
    'engine_rebuilt': build('m1b-python', lambda b: b.update(engine_sha256_after='b' * 64)),
    'build_missing': lambda d: edit(d, 'runs/m1bd-vcredist.json', lambda doc: doc.update(build=None)),
    'build_stale': build('m1b-node', lambda b: b.update(run_json_sha256='0' * 64)),
    'source_dirty': build('m1bd-traps-7zip', lambda b: b.update(source_dirty=True)),
    'two_commits': build('m1b-temurin', lambda b: b.update(commit='d' * 40)),
    'budget_engine_other': budget_runs(lambda doc: doc['engine_sha256'].update(m1b='9' * 64)),
    'traps_changed': append_ws('truth/m1b-traps.json'),
    'labels_override': lambda d: edit(d, 'manifest.json', lambda doc: doc['labels']['m1b-python'].update(label_id='python313')),
    'labels_changed': append_ws('truth/labels/node.json'),
    'frozen_missing': lambda d: os.remove(os.path.join(d, 'truth', 'frozen', 'temurin', 'truth.json')),
    'budget_exit': budget_runs(lambda doc: doc['runs'][3].update(exit=1)),
    'budget_two_rounds': budget_runs(lambda doc: doc.update(runs=[r for r in doc['runs'] if not (r['engine'] == 'm1b' and r['round'] == 3)])),
    # coordinator ruling 2026-11-18 (gate5): a 3-round record (before the fix) is not the 5 rounds K14 needs
    'budget_three_rounds': budget_runs(lambda doc: doc.update(runs=[r for r in doc['runs'] if r['round'] <= 3])),
    'budget_kept_cache': budget_runs(lambda doc: doc.update(cold_cache_state='kept', cold_cache=None)),
    'budget_kind': budget_runs(lambda doc: next(r for r in doc['runs'] if r['round'] == 2).update(kind='cold')),
    'no_safe_7zip': lambda d: edit(d, 'score-clean.json', lambda doc: (
        [i.update(band='Likely', preselected=False) for i in app_tool(doc, '7zip')['items']],
        app_tool(doc, '7zip').update(precision_safe=None))),
    # review R4c S2: the replay score holds the five runs and is bound to the gate's commit
    'replay_score_run_missing': lambda d: edit(d, 'replay-score.json', lambda doc: doc.update(
        apps=[a for a in doc['apps'] if a['id'] != 'npp'])),
    'replay_score_7zip_only': lambda d: edit(d, 'replay-score.json', lambda doc: doc.update(
        apps=[a for a in doc['apps'] if a['id'] == '7zip'])),
    'replay_score_no_block': lambda d: edit(d, 'replay-score.json', lambda doc: doc.pop('replay')),
    'replay_score_other_commit': lambda d: edit(d, 'replay-score.json', lambda doc: doc['replay'].update(commit='d' * 40)),
    'replay_score_dirty': lambda d: edit(d, 'replay-score.json', lambda doc: doc['replay'].update(source_dirty=None)),
    'replay_score_frozen_changed': append_ws('truth/frozen/npp/truth.json'),
    # review R4c S3: trap, label and guest files bound per run
    'inputs_missing': build('m1b-node', lambda b: b.pop('inputs')),
    'inputs_dirty': build('m1bcp-traps-7zip', lambda b: b.update(inputs_dirty=True)),
    'inputs_two_sets': build('m1bd-python', set_input('vm/guest/run-app.ps1', '1' * 64)),
    'inputs_changed_in_campaign': build('m1b-vcredist', set_input('vm/guest/m1b-traps.ps1', '2' * 64, after_only=True)),
    'inputs_traps_edited_before': all_builds(set_input('vm/truth/m1b-traps.json', '3' * 64)),
    'inputs_label_edited_before': all_builds(set_input('vm/truth/labels/node.json', '4' * 64)),
    # review R4c S4: run truth against frozen truth
    'sanity_relabelled': lambda d: edit(d, 'truth-clean-powershell.json', relabel('ambient')),
    'sanity_truth_missing': lambda d: os.remove(os.path.join(d, 'truth-clean-7zip.json')),
    'sanity_run_only': lambda d: edit(d, 'truth-clean-temurin.json', lambda doc: doc['items'].append(
        {'target': {'type': 'Path', 'path': 'C:\\Users\\rig\\.java'}, 'label': 'leftover', 'rule': 'default'})),
    'sanity_frozen_only': lambda d: edit(d, 'truth-clean-7zip.json', lambda doc: doc['items'].pop(0)),
    # the null runs (R4b S2 rest)
    'nulls_too_few': lambda d: edit(d, 'manifest.json', lambda doc: doc['nulls'].update(dirty=['m1bd-null1'])),
    'null_phase_failed': lambda d: edit(d, 'runs/m1bcp-null2.json', lambda doc: next(p for p in doc['run_json']['phases'] if p['name'] == 'snap0').update(ok=False)),
    # ruling 2026-11-18 (1): K1 / K8 count danger offered; a Blocked (deny-listed, report-only) danger item is kept
    'k1_blocked_denylisted': score_danger('clean', '7zip', 'Blocked'),
    'k1_danger_likely': score_danger('clean', 'python', 'Likely'),
    'k1_danger_safe': score_danger('cp', 'vcredist', 'Safe'),
    'k1_danger_likely_beside_kept': score_danger('clean', 'node', 'Blocked', 'Likely'),
    'k1_counts_disagree': lambda d: edit(d, 'score-clean.json', lambda doc: (
        set_danger(app_tool(doc, 'python'), [danger_item('Likely')]), app_tool(doc, 'python').update(danger_offered=0, danger_kept=1))),
    'k1_counts_missing': lambda d: edit(d, 'score-cp.json', lambda doc: app_tool(doc, 'python').pop('danger_offered')),
    'k8_vcredist_danger_likely': score_danger('dirty', 'vcredist', 'Likely'),
    'k8_vcredist_blocked': score_danger('dirty', 'vcredist', 'Blocked', 'Blocked'),
    # ruling 2026-11-18 (2): the install created the target (G3 node on dirty-base did not)
    'run_target_preinstalled': target('m1bd-temurin', in_lists0=True),
    'run_no_entry_created': target('m1b-node', entries_created=[]),
    'run_lists0_unreadable': target('m1bcp-vcredist', in_lists0=None),
    'run_target_unknown': lambda d: edit(d, 'runs/m1bd-traps-7zip.json', lambda doc: doc.update(target=None)),
    # ruling 2026-11-18 (Defender noise, RIG.md section 12.7): a Defender update between snap 0 and snap 2, or no
    # recorded versions, makes an app, trap or null run INVALID
    'run_defender_updated': defender('m1b-temurin', 'snap2', av_signature='1.465.120.0', as_signature='1.465.120.0'),
    'run_defender_engine_updated': defender('m1bd-7zip', 'snap2', engine='1.1.25110.1'),
    'run_defender_platform_updated': defender('m1bcp-vcredist', 'snap2', platform='4.18.25110.1'),
    'run_defender_missing': lambda d: edit(d, 'runs/m1bcp-python.json', lambda doc: doc['run_json'].pop('defender')),
    'run_defender_snap2_missing': defender('m1b-node', 'snap2'),
    'run_defender_no_signature': defender('m1bd-python', 'snap0', av_signature=None, source=None, error='Invalid namespace'),
    'trap_defender_updated': defender('m1bd-traps-7zip', 'snap2', av_signature='1.465.120.0'),
    'null_defender_updated': defender('m1b-null2', 'snap2', av_signature='1.465.120.0'),
    'null_defender_missing': lambda d: edit(d, 'runs/m1bd-null1.json', lambda doc: doc['run_json'].update(defender=None)),
    # positive: the registry fallback at one end (no platform version there), the same signatures: not an update
    'run_defender_registry_fallback': defender('m1b-python', 'snap2', platform=None, source='registry', error='MSFT_MpComputerStatus: timeout'),
    # positive (review R6 S1): the registry fallback's folder spelling of the same platform is not an update
    'run_defender_platform_folder_spelling': defender('m1b-python', 'snap2', platform='4.18.25100.9-0', source='registry'),
    # trap runs judge TrapA only (coordinator ruling 2026-11-18)
    'trap_main_is_pre': target('m1bd-traps-7zip', main_is_pre=True),
    'trap_main_not_created': target('m1bcp-traps-7zip', main_created=False),
    # ruling 2026-11-18 (3) / review R4d S2: an ambient item sharing the frozen leftover's normalised name
    'sanity_ambient_same_name': run_truth('python', temp_items(('DELEAE3.tmp', 'leftover'), ('6D5C.tmp', 'ambient'))),
    'sanity_ambient_only_same_name': run_truth('python', temp_items(('6D5C.tmp', 'ambient'))),
    'sanity_relabelled_by_name': run_truth('python', temp_items(('DELEAE3.tmp', 'kept_owner'), ('6D5C.tmp', 'ambient'))),
    'sanity_frozen_unreadable': lambda d: open(os.path.join(d, 'truth', 'frozen', 'node', 'truth.json'), 'w').write('{not json'),
    # review R4d S1: the deny list and the frozen truths are bound like the trap and label files
    'deny_changed': append_ws('truth/deny.json'),
    'inputs_deny_edited_before': all_builds(set_input('vm/truth/deny.json', '5' * 64)),
    'inputs_no_deny': all_builds(lambda b: (b['inputs'].pop('vm/truth/deny.json'), b['inputs_after'].pop('vm/truth/deny.json'))),
    'inputs_frozen_edited_before': all_builds(set_input('vm/truth/frozen/python/truth.json', '6' * 64)),
    # review R4d S3 / N1: the replay diff bound to the replay; an empty replayed plan
    'replay_diff_unbound': lambda d: edit(d, 'replay-score.json', lambda doc: doc['replay'].update(diff_sha256='0' * 64)),
    'replay_diff_failed': lambda d: edit(d, 'replay-score.json', lambda doc: doc['replay'].update(diff_exit=1)),
    'replay_diff_missing': lambda d: os.remove(os.path.join(d, 'replay-diff.json')),
    'replay_score_empty_plan': lambda d: edit(d, 'replay-score.json', lambda doc: app_tool(doc, 'git').update(items=[], offered_n=0)),
    'replay_score_no_counts': lambda d: edit(d, 'replay-score.json', lambda doc: app_tool(doc, 'firefox').pop('truth_n')),
    # ruling 2026-11-18 (5): K14 warm rounds read the disk cache; G7 like for like
    'budget_cache_memory': log_sub('m1b-harvest-2.log', r'msi_table_cache disk \S+ hits=\d+ misses=\d+', 'msi_table_cache memory'),
    'budget_cache_line_missing': log_sub('m1b-scan-3.log', r'^timing: msi_table_cache .*\n', ''),
    'budget_cache_no_hits': log_sub('m1b-scan-2.log', r'hits=\d+', 'hits=0'),
    'budget_warm_reads_tables': log_sub('m1b-harvest-3.log', r'fs\.metadata 505 0\.016s', 'fs.metadata 505 0.016s; sys.msi_tables 313/140094 3.180s'),
    'budget_not_like_for_like': all_of(*[log_sub(f'm2-harvest-{n}.log', r'1 root\(s\)', '0 root(s)') for n in (1, 2, 3, 4, 5)]),
    'budget_coproduct': log_sub('m1b-harvest-2.log', r'0 co-product', '1 co-product'),
    'budget_no_harvest_line': log_sub('m2-harvest-1.log', r'^harvest: .*\n', ''),
    # review R5 S1: the scores come from a rigtool built from vm/rigtool as collect found it
    'rigtool_unbound': lambda d: edit(d, 'manifest.json', lambda doc: doc['rigtool'].update(source_sha256='8' * 64)),
    'rigtool_no_source': lambda d: edit(d, 'manifest.json', lambda doc: doc['rigtool'].pop('source_sha256')),
    # review R5 S3: a Blocked danger item is kept only when the scan says DenyListed
    'k1_blocked_not_denylisted': scan_edit('clean', 'python', bam_blockers({'kind': 'NotGone'})),
    'k1_blocked_no_scan_item': scan_edit('clean', 'vcredist', lambda items: [i for i in items if i['target'] != BAM_SCAN]),
    'k1_blocked_no_scan': lambda d: os.remove(os.path.join(d, 'cp-vcredist-scan.json')),
    'k8_vcredist_blocked_too_large': scan_edit('dirty', 'vcredist', bam_blockers({'kind': 'TooLarge'})),
    # review R5 B1: the Launcher suggestion is a notice in the score, report-only, on rig-base and Clean-Pro
    'k8_suggestion_not_a_notice': lambda d: edit(d, 'score-clean.json', lambda doc: app_tool(doc, 'python').update(notices=[])),
    'k8_notices_missing': lambda d: edit(d, 'score-cp.json', lambda doc: app_tool(doc, 'python').pop('notices')),
    'k8_suggestion_not_report_only': scan_edit('clean', 'python', lambda items: [
        dict(i, action='DeleteKey') if i.get('scanner') == 'SYS-BURNDEPS' else i for i in items]),
    'k8_cp_no_suggestion': all_of(
        scan_edit('cp', 'python', lambda items: [i for i in items if i.get('scanner') != 'SYS-BURNDEPS']),
        lambda d: edit(d, 'score-cp.json', lambda doc: app_tool(doc, 'python').update(notices=[]))),
    # review R5 B2: dirty-base keeps the Launcher (Python 3.13.1): no suggestion, nothing of it offered
    'k8_dirty_python_suggestion': scan_edit('dirty', 'python', lambda items: items + [suggestion_item(LAUNCHER_313_KEY)]),
    'k8_dirty_launcher_offered': scan_edit('dirty', 'python', lambda items: items + [
        scan_item({'type': 'Path', 'path': 'C:\\Windows\\pyw.exe'}, 'Quarantine', 'Likely')]),
    'k8_dirty_launcher_blocked': scan_edit('dirty', 'python', lambda items: items + [
        scan_item({'type': 'Path', 'path': 'C:\\Windows\\pyshellext.amd64.dll'}, 'Quarantine', 'Blocked', (OTHER,)),
        scan_item({'type': 'RegKey', 'path': LAUNCHER_313_KEY}, 'ReportOnly', 'Likely')]),
    # review R5 B3: the cold scan is cold only when the cache the cold harvest filled is moved aside before it
    'budget_cold_scan_warm': kept_cold_scan,
    'budget_cold_scan_not_moved': budget_runs(lambda doc: doc['cold_cache_steps'].update(scan='kept')),
    'budget_cold_steps_missing': budget_runs(lambda doc: (doc.pop('cold_cache_steps'), doc.update(schema='purge.rig.m1b-budgets/2'))),
    # review R5b S1: a notice anywhere but on clean/cp python's Launcher Uninstall key
    'k8_notice_python313_with_312': lambda d: edit(d, 'score-clean.json', lambda doc: app_tool(doc, 'python313-with-312').update(
        notices=[notice(LAUNCHER_313_KEY)])),
    'k8_notice_7zip': lambda d: edit(d, 'score-cp.json', lambda doc: app_tool(doc, '7zip').update(notices=[notice()])),
    'k8_notices_missing_other': lambda d: edit(d, 'score-dirty.json', lambda doc: app_tool(doc, 'vcredist').pop('notices')),
    'k8_notice_not_launcher': python_suggestions('clean', NOT_LAUNCHER_KEY),
    'k8_notice_launcher_code_other_key': python_suggestions(
        'cp', 'HKLM\\SOFTWARE\\Classes\\Installer\\Dependencies\\{73831AC2-F0E1-4173-9FDB-D07463D7EB80}'),
    'k8_notice_second_not_launcher': python_suggestions('clean', LAUNCHER_KEY, NOT_LAUNCHER_KEY),
    'k8_notice_launcher_313': python_suggestions(
        'cp', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{7102CAE5-270C-4E81-AC25-27699156D8AE}'),
    # review R5b N1: a deny-listed scan item never covers another item, in the same or another user's hive
    'k1_blocked_deny_other_user': user_danger(f'HKU\\{SID}', (f'HKU\\{SID2}', (DENY,)), (f'HKU\\{SID}', (TOO_LARGE,))),
    'k1_blocked_deny_only_other_user': user_danger(f'HKU\\{SID}', (f'HKU\\{SID2}', (DENY,))),
    'k1_blocked_hkcu_two_users': user_danger('HKCU', (f'HKU\\{SID}', (DENY,)), (f'HKU\\{SID2}', (TOO_LARGE,))),
    'k1_blocked_same_key_two_items': user_danger(f'HKU\\{SID}', (f'HKU\\{SID}', (DENY,)), (f'HKU\\{SID}', (TOO_LARGE,))),
    'k1_blocked_user_hive_spelling': user_danger(f'HKU\\{SID}', ('HKCU', (DENY,))),
    'k1_blocked_user_hive_exact': user_danger(f'HKU\\{SID}', (f'HKU\\{SID}', (DENY,)), (f'HKU\\{SID2}', (TOO_LARGE,))),
}


# ------------------------------------------------------------------------------------------- freeze / prestate fixtures
# Synthetic inputs of `m1b.sh freeze`'s comparison (pyeval freezecmp) and of the pre-state kept_owner step (pyeval
# prestate), for the churn and K5 controls of the selftest (RIG.md sections 12.4, 12.6).
WU = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Orchestrator\\UScheduler'


def whole_run(run):
    return {'run': run, 'phases': [{'name': 'install', 'ok': True}, {'name': 'uninstall', 'ok': True}],
            'install': {'exit': 0, 'timed_out': False}, 'uninstall': {'exit': 0, 'timed_out': False, 'entry_gone': True},
            'main': {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{F1X}', 'name': 'Fixture'}}


def churn(d, variant):
    """Two freeze runs of app 'fx': a leftover in both (with a random temp name), Windows churn labelled leftover in
    one run only, ambient churn in one run only. Variants: ok, mismatch (the shared leftover labelled ambient in fz2),
    broken (fz1's ARP entry was not removed)."""
    if os.path.exists(d):
        shutil.rmtree(d)
    lo = {'target': {'type': 'RegKey', 'path': f'HKU\\{SID}\\Software\\Fixture'}, 'label': 'leftover', 'rule': 'default'}
    tmp = lambda r: {'target': {'type': 'Path', 'path': f'C:\\Users\\rig\\AppData\\Local\\Temp\\MSI{r}.LOG'}, 'label': 'leftover', 'rule': 'default'}
    wu = {'target': {'type': 'RegValue', 'path': WU, 'name': 'UpdateModelVersion'}, 'label': 'leftover', 'rule': 'default'}
    amb = {'target': {'type': 'Path', 'path': 'C:\\ProgramData\\Microsoft\\Windows\\WER\\Temp\\x.etl'}, 'label': 'ambient', 'rule': 'ambient:exact'}
    t1 = {'id': 'fx', 'items': [lo, tmp('1a2b3')]}
    t2 = {'id': 'fx', 'items': [dict(lo, label='ambient', rule='x') if variant == 'mismatch' else lo, tmp('9z8y7'), wu, amb]}
    r1, r2 = whole_run('m1b-fz1-fx'), whole_run('m1b-fz2-fx')
    if variant == 'broken':
        r1['uninstall']['entry_gone'] = False
    for k, t, r in ((1, t1, r1), (2, t2, r2)):
        wj(os.path.join(d, f'm1b-fz{k}-fx', 'truth.json'), t)
        wj(os.path.join(d, f'm1b-fz{k}-fx', 'run.json'), r)


def snap(path, recs):
    import gzip
    os.makedirs(os.path.dirname(path), exist_ok=True)
    esc = lambda s: s.replace('\\', '\\\\').replace('\t', '\\t')
    with gzip.open(path, 'wt', encoding='utf-8', newline='\n') as f:
        f.write('#purge-snap 1\t2026-11-17T00:00:00\tFIXTURE\tEnterpriseS\t26100.1\n')
        for r in recs:
            f.write('\t'.join([r[0]] + [esc(x) for x in r[1:]]) + '\n')


def prestate(d, here):
    """A python312-with-313 run whose Python Launcher (and 3.13) were installed before snap 0, with the committed
    label file: launcher objects in both snaps, one .py key that holds a leftover value, an object gone by snap 2."""
    if os.path.exists(d):
        shutil.rmtree(d)
    code, packed = '1A2B3C4D-0000-1111-2222-333344445555', 'D4C3B2A1000011112222333344445555'   # MSI packed form
    C = 'HKLM\\SOFTWARE\\Classes\\'
    UD = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\'
    un = 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{' + code + '}'
    k = lambda p: ('K', p, '1', '0', '0')
    v = lambda p, n, pv='': ('V', p, n, '1', '2', '0', pv)
    f = lambda p: ('F', p, '1', '20', '1', '0')
    both = [k(C + '.py'), v(C + '.py', '', 'Python.File'), k(C + '.py\\ShellNew'), k(C + '.pyw'), k(C + 'Python.File'),
            f('C:\\Windows\\py.exe'), f('C:\\Windows\\pyw.exe'), k(un), v(un, 'DisplayName', 'Python Launcher'),
            k(C + 'Installer\\Products\\' + packed), k(UD + 'Products\\' + packed + '\\InstallProperties'),
            v(UD + 'Products\\' + packed + '\\InstallProperties', 'LocalPackage', 'C:\\Windows\\Installer\\4f2a.msi'),
            f('C:\\Windows\\Installer\\4f2a.msi'), v(UD + 'Components\\0123456789ABCDEF0123456789ABCDEF', packed, 'C:\\Windows\\py.exe'),
            k(C + 'Installer\\Dependencies\\CPython-3.13_launcher'), v(C + 'Installer\\Dependencies\\CPython-3.13_launcher', '', '{' + code + '}'),
            f('C:\\Windows\\Installer\\9999.msi'), k('HKLM\\SOFTWARE\\Python\\PythonCore\\3.13')]
    s0 = both + [k(C + '.pyz')]                       # .pyz is gone by snap 2: not kept
    # a new value under .pyw (a leftover truth item inside it); Windows Installer's temp packages: 7777.msi (a leftover)
    # and 8888.msi (kept_owner by a generic cached-package rule) are listed, and so is the launcher's live LocalPackage
    TP = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\TempPackages'
    s2 = both + [v(C + '.pyw', 'Stale312', 'x'), f('C:\\Windows\\Installer\\7777.msi'), f('C:\\Windows\\Installer\\8888.msi'), k(TP),
                 v(TP, 'C:\\WINDOWS\\Installer\\7777.msi', '0'), v(TP, 'C:\\WINDOWS\\Installer\\8888.msi', '0'),
                 v(TP, 'C:\\Windows\\Installer\\4f2a.msi', '0')]
    run = 'm1b-python312-with-313'
    rd = os.path.join(d, run)
    snap(os.path.join(rd, f'snap-{run}-0.tsv.gz'), s0)
    snap(os.path.join(rd, f'snap-{run}-2.tsv.gz'), s2)
    ent = {'key': un, 'name': 'Python Launcher', 'version': '3.13.17', 'msi': '{' + code + '}'}
    gone = {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{DEAD}', 'name': 'Python Launcher', 'msi': '{DEADBEEF-0000-0000-0000-000000000000}'}
    wj(os.path.join(rd, f'lists-{run}-0.json'), {'uninstall': [ent, gone]})
    wj(os.path.join(rd, f'lists-{run}-2.json'), {'uninstall': [ent]})
    wj(os.path.join(rd, 'truth.json'), {'id': 'python312-with-313', 'counts': {'leftover': 1}, 'items': [
        {'target': {'type': 'RegValue', 'path': C + '.pyw', 'name': 'Stale312'}, 'label': 'leftover', 'rule': 'default'},
        {'target': {'type': 'Path', 'path': 'C:\\WINDOWS\\Installer\\7777.msi'}, 'label': 'leftover', 'rule': 'default'},
        {'target': {'type': 'Path', 'path': 'C:\\WINDOWS\\Installer\\8888.msi'}, 'label': 'kept_owner', 'rule': 'labels: generic'}]})
    shutil.copy(os.path.join(here, 'labels', 'python312-with-313.json'), os.path.join(d, 'labels.json'))


NODE_KEY = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{F3A57DD0-5D8B-4A74-A055-670A7BAA4176}'


def targetruns(d):
    """Two run dirs for `pyeval runsum` (ruling 2026-11-18, RUN): m1bd-node as the failed campaign had it (dirty-base's
    Node.js 20.18.0 already in lists-0, nothing created) and m1bd-temurin (a new entry)."""
    if os.path.exists(d):
        shutil.rmtree(d)
    node = {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{F3A57DD0-5D8B-4A74-A055-670A7BAA4176}',
            'name': 'Node.js', 'version': '20.18.0', 'msi': '{F3A57DD0-5D8B-4A74-A055-670A7BAA4176}'}
    tem = {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{0A1B2C3D-1111-2222-3333-444455556666}',
           'name': 'Eclipse Temurin JDK with Hotspot 21.0.13+9 (x64)', 'version': '21.0.13.9', 'msi': '{0A1B2C3D-1111-2222-3333-444455556666}'}
    for run, main, created in (('m1bd-node', node, []), ('m1bd-temurin', tem, [tem])):
        rd = os.path.join(d, run)
        rjd = {'schema': 'purge.rig.run/1', 'run': run, 'finished': 'x', 'main': main,
               'entries_created': created, 'phases': [{'name': 'install', 'ok': True}]}
        if run == 'm1bd-temurin':   # the guest's record (riglib Wait-DefenderIdle, Get-DefenderVersions)
            v = dict(DEF_V, nis_signature='1.465.100.0', av_signature_updated='2026-11-18T09:00:00Z', at='2026-11-18T09:01:00Z')
            # gate5 fix: MpCmdRun busy (exit 2) once, then exit 0; signatures current at the end
            att = [{'exe': 'MpCmdRun.exe', 'n': 1, 'exit': 2, 'timed_out': False, 'sec': 0.1, 'error': None},
                   {'exe': 'MpCmdRun.exe', 'n': 2, 'exit': 0, 'timed_out': False, 'sec': 14.1, 'error': None}]
            rjd['defender'] = {'idle': {'method': 'x', 'stable': True, 'current': True, 'bounded': False, 'updated': True, 'changes': 1,
                                        'waited_sec': 75.2, 'error': None, 'before': dict(v, av_signature='1.463.242.0'), 'after': v,
                                        'attempts': att, 'trigger': att[-1]},
                               'snap0': v, 'snap2': dict(v, av_signature='1.465.120.0')}
        wj(os.path.join(rd, 'run.json'), rjd)
        # lists-0 names the node entry under another key casing (a key compare is case-insensitive)
        wj(os.path.join(rd, f'lists-{run}-0.json'), {'uninstall': [dict(node, key=node['key'].upper())]})
    # dirty trap runs (coordinator ruling 2026-11-18): TrapB node is a pre-app, in lists-0 by design; TrapA 7zip is
    # the target. trapok: TrapA new; trapa0: TrapA's entry already in lists-0 too (entries_created kept, so the
    # lists-0 rule alone decides); trappre: run.json main names the TrapB entry.
    zip7 = {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip', 'name': '7-Zip 24.08 (x64 edition)',
            'version': '24.08.00.0', 'msi': None}
    # review R5 S2: trapnopre: run.json has no `pre`; trapemptypre: `pre` is an empty list (the pre-app phase
    # recorded nothing). Both must be INVALID ("cannot tell whether the target is TrapA").
    for var, main, l0 in (('trapok', zip7, [node]), ('trapa0', zip7, [node, zip7]), ('trappre', node, [node]),
                          ('trapnopre', zip7, [node]), ('trapemptypre', zip7, [node])):
        run = 'm1bd-traps-7zip'
        rd = os.path.join(d, var, run)
        rjd = {'schema': 'purge.rig.run/1', 'run': run, 'finished': 'x', 'main': main,
               'pre': [{'id': 'node', 'exit': 0, 'entry': dict(node)}],
               'entries_created': [zip7], 'phases': [{'name': 'install', 'ok': True}]}
        if var == 'trapnopre':
            rjd.pop('pre')
        elif var == 'trapemptypre':
            rjd['pre'] = []
        wj(os.path.join(rd, 'run.json'), rjd)
        wj(os.path.join(rd, f'lists-{run}-0.json'), {'uninstall': l0})


def planactions(d):
    """A plan and its scan sidecar for plan_actions: the Launcher suggestion (ReportOnly + suggest_uninstall), a
    deleting item, and a plain ReportOnly item without the fact."""
    if os.path.exists(d):
        shutil.rmtree(d)
    k = lambda p: {'type': 'RegKey', 'path': p}
    py = 'HKLM\\SOFTWARE\\Python\\PythonCore\\Python312'
    stale = 'HKLM\\SOFTWARE\\Fixture\\Stale'
    wj(os.path.join(d, 'plan.json'), {'items': [
        {'target': k(LAUNCHER_KEY), 'band': 'Likely', 'preselected': False, 'suggest_uninstall': 'stale value'},
        {'target': k(py), 'band': 'Safe', 'preselected': True},
        {'target': k(stale.upper()), 'band': 'Weak', 'preselected': False}]})
    wj(os.path.join(d, 'scan.json'), {'items': [suggestion_item(), scan_item(k(py), 'DeleteKey', 'Safe'),
                                                scan_item(k(stale), 'ReportOnly', 'Weak')]})


def settarget(d, run, runsum):
    """Puts the target `pyeval runsum` recorded into a fixture evidence run record."""
    t = rj(runsum)['target']
    edit(d, f'runs/{run}.json', lambda doc: doc.update(target=t))


# ------------------------------------------------------------------------------------------- replay step stubs
# `m1b.sh replay` (review R4c S2) with stub commands: the frozen runs, cargo xtask, rigtool score and git.
def replayruns(d, skip=None):
    if os.path.exists(d):
        shutil.rmtree(d)
    for a in REPLAY_IDS:
        if a == skip:
            continue
        rd = os.path.join(d, a)
        wj(os.path.join(rd, 'run.json'), {'schema': 'purge.rig.run/1', 'id': a, 'run': a})
        wj(os.path.join(rd, f'lists-{a}-0.json'), {'uninstall': []})
        for ph in ('0', '2'):
            snap(os.path.join(rd, f'snap-{a}-{ph}.tsv.gz'), [])
        os.makedirs(os.path.join(rd, 'plans'))   # the frozen run's own plans: the step must not write here


def opt(args, name):
    return args[args.index(name) + 1] if name in args else None


def xtask(here, args):
    if args[0] == 'replay-diff':
        if os.environ.get('STUB_DIFF_FAIL'):   # replay-diff failing before it writes (review R4d S3)
            raise SystemExit('xtask stub: replay-diff failed')
        shutil.copy(os.path.join(here, 'm1b-replay-diff.json'), opt(args, '-o'))
    elif args[0] == 'replay':
        run, app, out = opt(args, '--run'), opt(args, '--app'), opt(args, '-o')
        if not os.path.isfile(os.path.join(run, 'run.json')):
            raise SystemExit(f'xtask stub: no run {run}')
        t = {'type': 'RegKey', 'path': f'HKU\\{SID}\\Software\\7-Zip' if app == '7zip' else f'HKLM\\SOFTWARE\\Fixture\\{app}'}
        wj(out, {'app': app, 'items': [{'target': t, 'band': 'Safe', 'preselected': True}]})
        wj(out[:-5] + '.scan.json', {'items': [{'target': t, 'action': 'DeleteKey'}]})
    else:
        raise SystemExit(f'xtask stub: {args}')


def rigtool(args):
    """rigtool score --set <dirs> ... --json J: one purge score per dir, needing truth.json, both snaps and plans
    with actions (the step's plan_actions ran)."""
    if args[0] == 'version':   # review R5 S1: the sources the stub "was built from" (STUB_RIGTOOL_SHA)
        print(f"rigtool 0.0.0 source-sha256 {os.environ.get('STUB_RIGTOOL_SHA')}" if os.environ.get('STUB_RIGTOOL_SHA') else 'rigtool 0.0.0')
        return
    if args[0] != 'score':
        raise SystemExit(f'rigtool stub: {args}')
    dirs = args[args.index('--set') + 1:]
    dirs = dirs[:next((i for i, x in enumerate(dirs) if x.startswith('--')), len(dirs))]
    apps = []
    for d in dirs:
        a = os.path.basename(os.path.normpath(d))
        for f in ('truth.json', f'snap-{a}-0.tsv.gz', f'snap-{a}-2.tsv.gz', 'plans/purge.json'):
            if not os.path.isfile(os.path.join(d, f)):
                raise SystemExit(f'rigtool stub: {d}: no {f}')
        if len(os.listdir(os.path.join(d, 'plans'))) != 1:
            raise SystemExit(f'rigtool stub: {d}: plans/ holds more than the purge plan')
        plan = rj(os.path.join(d, 'plans', 'purge.json'))
        if any(not i.get('action') for i in plan['items']):
            raise SystemExit(f'rigtool stub: {d}: a plan item without its sidecar action')
        items = [{'target': 'K:' + i['target']['path'], 'band': i['band'], 'preselected': i['preselected'], 'outcome': 'hit'}
                 for i in plan['items']]
        apps.append({'id': rj(os.path.join(d, 'truth.json')).get('id') or a, 'dir': d,
                     'tools': [{'tool': 'purge', 'danger_listed': 0, 'precision_safe': 1.0, 'truth_n': 3,
                                'offered_n': len(items), 'items': items}]})
    wj(opt(args, '--json'), {'apps': apps})


def git(args):
    if 'rev-parse' in args:
        print(COMMIT)
    elif 'status' in args:
        if os.environ.get('STUB_GIT_DIRTY'):
            print(' M src/score.rs')
    else:
        raise SystemExit(f'git stub: {args}')


def main(argv):
    if len(argv) >= 3 and argv[1] == 'xtask':
        xtask(argv[2], argv[3:])
        return
    if len(argv) >= 2 and argv[1] in ('rigtool', 'git'):
        (rigtool if argv[1] == 'rigtool' else git)(argv[2:])
        return
    if len(argv) in (3, 4) and argv[1] == 'replayruns':
        replayruns(argv[2], argv[3] if len(argv) == 4 else None)
        return
    if len(argv) == 2 and argv[1] == 'nullmap':
        print(' '.join(NULL_RUNS))
        return
    if len(argv) == 3 and argv[1] == 'targetruns':
        targetruns(argv[2])
        return
    if len(argv) == 3 and argv[1] == 'planactions':
        planactions(argv[2])
        return
    if len(argv) == 5 and argv[1] == 'settarget':
        settarget(argv[2], argv[3], argv[4])
        return
    if len(argv) == 4 and argv[1] == 'write':
        write(argv[2], argv[3])
    elif len(argv) == 4 and argv[1] == 'churn':
        churn(argv[2], argv[3])
    elif len(argv) == 4 and argv[1] == 'prestate':
        prestate(argv[2], argv[3])
    elif len(argv) == 2 and argv[1] == 'labelmap':
        print(labelmap())
    elif len(argv) == 4 and argv[1] == 'mutate':
        if argv[3] not in MUTATIONS:
            raise SystemExit(f'unknown mutation {argv[3]}')
        MUTATIONS[argv[3]](argv[2])
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv)
