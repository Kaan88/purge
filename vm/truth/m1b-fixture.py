"""Evidence for the m1b.sh selftest (review R4b): a SYNTHETIC evidence dir that passes the M1b scan gate in its default
configuration, and the bad-run mutations that must make it fail. Not a VM capture; numbers are illustrative only.

    python -I m1b-fixture.py write <dir> <vm/truth dir>   the passing evidence dir; <dir>/truth/ holds a copy of the
                                                          committed trap file and label files and a fixture frozen truth
                                                          of powershell and temurin
    python -I m1b-fixture.py labelmap                     the "run=label-id ..." map collect would write
    python -I m1b-fixture.py mutate <dir> <name>          one bad-run control (names: MUTATIONS below)

The manifest is written by m1b.sh itself (pyeval manifest), as collect writes it. The replay diff is the committed
vm/truth/m1b-replay-diff.json, so the selftest fails when the scorer and the committed diff disagree (R4b B1).
"""
import hashlib
import json
import os
import shutil
import sys

SID = 'S-1-5-21-1000000000-2000000000-3000000000-1001'
APPS = ['7zip', 'python', 'python312-with-313', 'python313-with-312', 'node', 'vcredist', 'powershell', 'temurin']
CP_APPS = ['7zip', 'python', 'vcredist']
PREFIX = {'clean': 'm1b', 'dirty': 'm1bd', 'cp': 'm1bcp'}
TRAP_RUNS = ['m1b-traps-7zip', 'm1bd-traps-7zip', 'm1bcp-traps-7zip']
ENGINE = 'e' * 64
COMMIT = 'c' * 40


def wj(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


def rj(path):
    with open(path, encoding='utf-8-sig') as f:
        return json.load(f)


def set_apps(s):
    return CP_APPS if s == 'cp' else APPS


def app_runs():
    return [(s, a, f'{PREFIX[s]}-{a}') for s in ('clean', 'dirty', 'cp') for a in set_apps(s)]


def item(target, band='Safe', pre=None, outcome='hit'):
    return {'target': target, 'band': band, 'preselected': band == 'Safe' if pre is None else pre, 'outcome': outcome}


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
    return {'tool': 'purge', 'truth_n': 3, 'offered_n': len(items), 'danger_listed': 0, 'danger_blocking': 0,
            'danger_preselected': 0, 'userdata_preselected': 0,
            'precision_safe': 1.0 if any(i['band'] == 'Safe' for i in items) else None,
            'protected_n': pn, 'protected_correct': 1.0 if pn else None, 'protected_wrong': [], 'items': items}


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


def run_doc(run, phases):
    sha = hashlib.sha256(('run.json of ' + run).encode()).hexdigest()
    return {'schema': 'purge.rig.m1b-run/1', 'run': run, 'run_json_sha256': sha,
            'run_json': {'run': run, 'started': '2026-11-17T09:00:00+01:00', 'finished': '2026-11-17T09:40:00+01:00',
                         'phases': [{'name': p, 'ok': True, 'error': None} for p in phases]},
            'build': {'schema': 'purge.rig.m1b-build/1', 'run': run, 'run_json_sha256': sha, 'engine': 'purge-engine.exe',
                      'engine_sha256': ENGINE, 'engine_sha256_after': ENGINE, 'commit': COMMIT, 'source_dirty': False},
            'plan_items': 2}


APP_PHASES = ['setup', 'install', 'launch', 'lists1', 'engine-inventory-1', 'snap1', 'msi-tables-1', 'engine-harvest',
              'uninstall', 'lists2', 'engine-inventory-2', 'snap2', 'msi-tables-2', 'edge-check', 'entries', 'engine-scan']
TRAP_PHASES = ['setup', 'pre-node', 'install', 'launch', 'm1b-traps-pre', 'lists1', 'snap1', 'msi-tables-1', 'engine-harvest',
               'm1b-traps-between', 'uninstall', 'm1b-traps-post', 'lists2', 'snap2', 'msi-tables-2', 'engine-scan']


def budget_log(engine, step, kind):
    total = {('m1b', 'harvest'): 9.0, ('m2', 'harvest'): 7.5, ('m1b', 'scan'): 8.0, ('m2', 'scan'): 6.5}[(engine, step)]
    if kind == 'cold':
        total += 3.0
    lines = ['[  0.010s] purge-engine ' + step]
    if engine == 'm1b':
        if step == 'scan':
            lines.append('timing: phase refscan 1.200s')
        lines.append('timing: phase ownership.components 0.800s')
        lines.append('timing: phase ownership.tables %.3fs' % (2.5 if kind == 'cold' else 0.1))
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
    for a in ('powershell', 'temurin'):
        wj(os.path.join(d, 'truth', 'frozen', a, 'truth.json'), {'schema': 'fixture', 'app': a, 'items': []})
    # scores
    for s in ('clean', 'dirty', 'cp'):
        wj(os.path.join(d, f'score-{s}.json'),
           {'apps': [{'id': a, 'dir': f'runs/{PREFIX[s]}-{a}', 'tools': [tool(a)]} for a in set_apps(s)]})
    wj(os.path.join(d, 'clean-7zip-fp.json'), {'roots': [{'path': 'C:\\Program Files\\7-Zip', 'source': 'MsiComponent'}]})
    for s in ('clean', 'dirty'):
        wj(os.path.join(d, f'{s}-python-scan.json'),
           {'items': [{'action': 'ReportOnly', 'related': {'suggest_uninstall': 'Python Launcher (64-bit)'}}]})
        wj(os.path.join(d, f'{s}-python312-with-313-scan.json'), {'items': []})
    # replay (G1)
    wj(os.path.join(d, 'replay-score.json'), {'apps': [
        {'id': a, 'tools': [{'tool': 'purge', 'danger_listed': 0, 'precision_safe': 1.0,
                             'items': [item(f'K:HKU\\{SID}\\Software\\7-Zip')] if a == '7zip' else []}]}
        for a in ('vscode', 'git', 'firefox', 'npp', '7zip')]})
    shutil.copy(os.path.join(here, 'm1b-replay-diff.json'), os.path.join(d, 'replay-diff.json'))
    # traps
    traps = rj(os.path.join(here, 'm1b-traps.json'))
    for run in TRAP_RUNS:
        wj(os.path.join(d, f'traps-{run}.json'), {'summary': {'cases': 26, 'expectations': 44, 'met': 44, 'escapes': 0, 'missed_owned': 0}})
        wj(os.path.join(d, f'traps-planted-{run}.json'), planted_doc(traps))
    # run records
    for _, _, run in app_runs():
        wj(os.path.join(d, 'runs', f'{run}.json'), run_doc(run, APP_PHASES))
    for run in TRAP_RUNS:
        wj(os.path.join(d, 'runs', f'{run}.json'), run_doc(run, TRAP_PHASES))
    # budgets (G7)
    runs = []
    os.makedirs(os.path.join(d, 'budgets'), exist_ok=True)
    for e in ('m1b', 'm2'):
        for n in (1, 2, 3):
            kind = 'cold' if n == 1 else 'warm'
            for step in ('harvest', 'scan'):
                log = f'{e}-{step}-{n}.log'
                with open(os.path.join(d, 'budgets', log), 'w', encoding='utf-8') as f:
                    f.write(budget_log(e, step, kind))
                runs.append({'engine': e, 'step': step, 'round': n, 'kind': kind, 'log': log, 'exit': 0, 'wall_s': 5.0})
    wj(os.path.join(d, 'budgets', 'budgets.json'),
       {'schema': 'purge.rig.m1b-budgets/2', 'program': 'fixture-program', 'host': 'FIXTURE', 'engines': {'m1b': 'm1b.exe', 'm2': 'm2.exe'},
        'engine_sha256': {'m1b': ENGINE, 'm2': 'f' * 64}, 'cold_cache_state': 'moved', 'cold_cache': 'msitables.aside', 'runs': runs})


def labelmap():
    return ' '.join(f'{run}={a}' for _, a, run in app_runs())


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


MUTATIONS = {
    'replay_committed_diff': lambda d: None,
    'replay_promotion_unexplained': lambda d: edit(d, 'replay-diff.json', add_row('new_scanner')),
    'replay_justified_not_listed': lambda d: edit(d, 'replay-diff.json', add_row('promotion_justified')),
    'replay_justified_listed': lambda d: edit(d, 'replay-diff.json', add_row('promotion_justified', listed=True)),
    'replay_justified_no_promotion': lambda d: edit(d, 'replay-diff.json', add_row('promotion_justified', listed=True, demote=True)),
    'replay_sixth_reason': lambda d: edit(d, 'replay-diff.json', lambda doc: doc['reasons'].append('looks_fine')),
    'replay_run_missing': lambda d: edit(d, 'replay-diff.json', lambda doc: doc['apps'].pop('7zip')),
    'replay_old_schema': lambda d: edit(d, 'replay-diff.json', lambda doc: doc.update(schema='purge.replay-diff/2')),
    'k6_leftover_weak': lambda d: edit(d, 'score-clean.json', lambda doc: (
        app_tool(doc, 'node')['items'].append(item('P:C:\\Users\\rig\\AppData\\Local\\Temp\\node-x.log', 'Weak')),
        app_tool(doc, 'node').update(offered_n=2))),
    'k6_preselected_likely': lambda d: edit(d, 'score-clean.json', lambda doc: app_tool(doc, '7zip')['items'][1].update(band='Likely', preselected=True)),
    'k6_unknown_band': lambda d: edit(d, 'score-dirty.json', lambda doc: app_tool(doc, 'node')['items'][0].update(band='Maybe')),
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
    'run_phase_failed': lambda d: edit(d, 'runs/m1b-traps-7zip.json', lambda doc: doc['run_json']['phases'][4].update(ok=False, error='a case failed')),
    'run_unfinished': lambda d: edit(d, 'runs/m1bcp-python.json', lambda doc: doc['run_json'].update(finished=None)),
    'run_json_missing': lambda d: os.remove(os.path.join(d, 'runs', 'm1bd-node.json')),
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
    'budget_kept_cache': budget_runs(lambda doc: doc.update(cold_cache_state='kept', cold_cache=None)),
    'budget_kind': budget_runs(lambda doc: next(r for r in doc['runs'] if r['round'] == 2).update(kind='cold')),
    'no_safe_7zip': lambda d: edit(d, 'score-clean.json', lambda doc: (
        [i.update(band='Likely', preselected=False) for i in app_tool(doc, '7zip')['items']],
        app_tool(doc, '7zip').update(precision_safe=None))),
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


def main(argv):
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
