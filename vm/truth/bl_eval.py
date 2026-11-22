"""Helpers of truth/bl.sh (BL-GATE scorer): runinfo, runrec, summary, evaluate, mutate (the self-test's
mutations). Read bl.sh's header for the criteria. Everything that cannot be read is a FAIL, never a skip."""
import datetime, gzip, hashlib, json, os, re, sys

MODE, A = sys.argv[1], sys.argv[2:]
E = os.environ
BANDS = {'Blocked': 1, 'Weak': 2, 'Likely': 3, 'Safe': 4}
REG = ('RegKey', 'RegValue', 'RegValueChanged', 'RegMultiSzSegment')
VIEWS = ['exact', 'none', 'merged', 'local']
BELOW = ['merged', 'local']


def load(p):
    try:
        with open(p, encoding='utf-8-sig') as f:
            return json.load(f)
    except Exception:  # missing or unparsable: the caller FAILs
        return None


def sha256(p):
    try:
        with open(p, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


def write(p, doc):
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2)


if MODE == 'runinfo':  # runinfo <run.json> -> "<app id>\t<os>"
    d = load(A[0])
    if not isinstance(d, dict) or not d.get('id') or not d.get('os'):
        sys.exit(1)
    sys.stdout.buffer.write(f"{d['id']}\t{d['os']}\n".encode())
    sys.exit(0)

if MODE == 'runrec':  # runrec <out> <run> <id> <os> <local> <neighbour> <view:exit:secs>...
    out, run, app, osn, loc, nb = A[:6]
    views = {}
    for rec in A[6:]:
        v, rc, secs = rec.split(':')
        p = os.path.join(os.path.dirname(out), v + '.json')
        views[v] = {'exit': int(rc), 'secs': int(secs), 'plan_sha256': sha256(p)}
    write(out, {'schema': 'purge.rig.bl-run/1', 'run': run, 'app': app, 'os': osn, 'local': loc,
                'local_sha256': sha256(loc), 'neighbour': nb, 'neighbour_sha256': sha256(nb), 'views': views})
    sys.exit(0)

if MODE == 'summary':  # summary <out> <started> <commit> <dirty char> <local inbound> <local cleanpro>
    out, started, commit, dirty = A[:4]
    corpus = E['BL_RUNS'].split()
    runs = [r for r in corpus if load(os.path.join(os.path.dirname(out), r, 'bl-run.json'))]
    write(out, {'schema': 'purge.rig.bl-r3/1', 'started': started, 'finished': now(), 'commit': commit or None,
                'source_dirty': bool(dirty), 'corpus': corpus, 'runs': runs,
                'locals': {p: sha256(p) for p in A[4:6]}})
    print(f'bl replay: {len(runs)} of {len(corpus)} run(s) replayed -> {out}', file=sys.stderr)
    sys.exit(0 if len(runs) == len(corpus) and runs else 1)


# ------------------------------------------------------------------------------------------- plan comparisons
def tkey(t):
    return json.dumps(t, sort_keys=True).lower()


def inside(inner, outer):
    i, o = inner.lower().rstrip('\\'), outer.lower().rstrip('\\')
    return i == o or i.startswith(o + '\\')


def covers(outer, inner):
    """xtask replay::covers: the same target, a key over a registry target, a directory over a path."""
    if outer.get('type') == 'RegKey' and inner.get('type') in REG:
        return inside(inner.get('path', ''), outer.get('path', ''))
    if outer.get('type') == 'Path' and inner.get('type') == 'Path':
        return inside(inner.get('path', ''), outer.get('path', ''))
    return tkey(outer) == tkey(inner)


def plan(p):
    """The items of a purge.plan/0 document, or a reason why it is not one."""
    d = load(p)
    if not isinstance(d, dict) or d.get('schema') != 'purge.plan/0' or not isinstance(d.get('items'), list):
        return None, f'{p}: missing or not a purge.plan/0 document'
    for i in d['items']:
        if not (isinstance(i, dict) and isinstance(i.get('target'), dict) and i.get('band') in BANDS
                and isinstance(i.get('preselected'), bool)):
            return None, f'{p}: an item without target, band or preselected'
    return d['items'], None


def stronger(ref, item):
    """Some item of `ref` of the item's target (or, when there is none, covering it) offers it at least as
    strongly: band at least as high, preselected if the item is (xtask l5_violations, also used for flips)."""
    same = [n for n in ref if tkey(n['target']) == tkey(item['target'])]
    cov = same or [n for n in ref if covers(n['target'], item['target'])]
    if not cov:
        return 'new'
    if not any(BANDS[n['band']] >= BANDS[item['band']] for n in cov):
        return 'raised'
    if item['preselected'] and not any(n['preselected'] and BANDS[n['band']] >= BANDS[item['band']] for n in cov):
        return 'preselected'
    return None


def offered(items):
    return {tkey(i['target']): i for i in items if i['band'] != 'Blocked'}


_truth = {}


def in_truth(osn, target):
    """Whether the truth (exact shipped) baseline has the item's key, value or path; None when it cannot be read."""
    name = (osn or '').replace(' ', '-')
    if name not in _truth:
        recs = set()
        try:
            with gzip.open(os.path.join(E['BL_KB'], name + '.tsv.gz'), 'rt', encoding='utf-8') as f:
                for line in f:
                    p = line.rstrip('\n').split('\t')
                    if p[0] in ('K', 'D', 'F') and len(p) > 1:
                        recs.add((p[0], p[1].replace('\\\\', '\\').lower()))
                    elif p[0] == 'V' and len(p) > 2:
                        recs.add(('V', p[1].replace('\\\\', '\\').lower() + '|' + p[2].lower()))
        except (OSError, EOFError, UnicodeDecodeError):
            recs = None
        _truth[name] = recs
    recs, t, path = _truth[name], target.get('type'), target.get('path', '').lower()
    if recs is None:
        return None
    if t == 'RegKey':
        return ('K', path) in recs
    if t in REG:
        return ('V', path + '|' + str(target.get('name', '')).lower()) in recs or ('K', path) in recs
    if t == 'Path':
        return ('D', path) in recs or ('F', path) in recs
    return None


# ------------------------------------------------------------------------------------------- evaluate
if MODE == 'evaluate':
    OUT, rows = E['BL_OUT'], []

    def row(cid, kind, subject, value, limit, ok):
        rows.append({'id': cid, 'kind': kind, 'subject': subject, 'value': value, 'limit': limit, 'pass': bool(ok)})

    UFH_SHC = re.compile(r'^V:HKU\\[^\\|]+\\Software\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC\|', re.I)
    SET_TAG = {'clean': 'm1b', 'dirty': 'm1bd', 'cp': 'm1bcp'}

    def purge_tool(doc, app):
        for a in (doc or {}).get('apps', []) if isinstance(doc, dict) else []:
            if a.get('id') == app:
                for t in a.get('tools', []):
                    if t.get('tool') == 'purge':
                        return t
        return None

    def empty_plan_explained(m, p, c, mine):
        """R4 ruling (coordinator 2026-11-22, DECISIONS): m1b.sh fails K1/K2/K3 of an app whose plan is empty while
        its truth has leftovers. Below Exact that is a recall cost, not a safety failure, in one case only: the exact
        M1b gate run of the same set and app offered items and every one was a UFH\\SHC slot value, which BL-FIX-UFH
        makes Windows-owned below Exact. Also required: the app's RUN row passed (the engine ran and every phase was
        ok); this run's plan offered nothing (offered_n 0) and listed no danger (danger_listed 0); and the R3 replay of
        that same exact gate run with this view, made by the engine under test, offers nothing either (ties the claim
        "no view below Exact offers these" to this build; a missing R3 plan fails closed). Anything else stays S1."""
        if c.get('pass') is True or c.get('id') not in ('K1', 'K2', 'K3'):
            return False
        if not str(c.get('value', '')).startswith('empty plan:'):
            return False
        s, _, app = str(c.get('subject', '')).partition('/')
        if s not in SET_TAG or not app:
            return False
        run = f'{p}-{SET_TAG[s]}-{app}'
        if not any(r.get('id') == 'RUN' and r.get('subject') == run and r.get('pass') is True for r in mine):
            return False
        ref = purge_tool(load(os.path.join(E['BL_EXACT_EVID'], f'score-{s}.json')), app)
        got = purge_tool(load(os.path.join(OUT, f'r4-{m}', 'm1b-evidence', f'score-{s}.json')), app)
        if not ref or not got:
            return False
        items = ref.get('items')
        # The score's items are every offered item (offered_n of them), so "all UFH\SHC" covers the whole exact plan.
        if not isinstance(items, list) or not items or ref.get('offered_n') != len(items):
            return False
        if not all(isinstance(i, dict) and UFH_SHC.match(str(i.get('target', ''))) for i in items):
            return False
        if got.get('offered_n') != 0 or got.get('danger_listed') != 0:
            return False
        replayed, _ = plan(os.path.join(OUT, 'r3', f'{SET_TAG[s]}-{app}', f'{m}.json'))
        return replayed is not None and not offered(replayed)

    # R3
    r3 = os.path.join(OUT, 'r3')
    summ = load(os.path.join(r3, 'summary.json'))
    corpus = E['BL_RUNS'].split()
    runs = summ.get('runs') if isinstance(summ, dict) and summ.get('schema') == 'purge.rig.bl-r3/1' else None
    if not isinstance(runs, list) or not runs:
        for cid in ('S1', 'S4'):
            row(cid, 'S', 'R3', f'missing: no runs in {r3}/summary.json (bash truth/bl.sh replay)', '>= 1 run', False)
        runs = []
    elif not corpus or sorted(summ.get('corpus') or []) != sorted(corpus) or sorted(runs) != sorted(corpus):
        row('S1', 'S', 'R3 corpus', f"replayed {len(runs)} of {len(corpus)}: missing "
            f"{sorted(set(corpus) - set(runs)) or 'none'}, corpus {'equal' if sorted(summ.get('corpus') or []) == sorted(corpus) else 'differs'}",
            'every corpus run replayed', False)
    flips = {m: [] for m in BELOW}
    listed_blocked = {m: 0 for m in BELOW}
    w2 = {m: [0, 0] for m in BELOW}   # [offered as Likely, exact-only key candidates]
    w3 = {m: [0, 0] for m in BELOW}   # [exact and none offer, the view does not; exact offered]
    l5_checked = 0
    judged = 0   # runs with all four plans
    for r in runs:
        rec = load(os.path.join(r3, r, 'bl-run.json'))
        plans, bad = {}, []
        for v in VIEWS:
            st = (rec or {}).get('views', {}).get(v) if isinstance(rec, dict) else None
            if not isinstance(st, dict):
                bad.append(f'{v}: no record'); continue
            items, why = plan(os.path.join(r3, r, v + '.json'))
            if items is None:
                bad.append(why); continue
            if v in ('exact', 'none') and st.get('exit') != 0:
                bad.append(f"{v}: replay exit {st.get('exit')}"); continue
            plans[v] = items
        if bad:
            for cid in ('S1', 'S4'):
                row(cid, 'S', r, 'missing or unreadable: ' + '; '.join(bad), 'four plans', False)
            continue
        judged += 1
        ex, no, osn = plans['exact'], plans['none'], rec.get('os')
        ex_off, no_off = offered(ex), offered(no)
        for m in BELOW:
            below = plans[m]
            for i in below:
                why = stronger(ex, i)
                if why == 'new' and i['band'] == 'Blocked' and not i['preselected']:
                    listed_blocked[m] += 1
                elif why:
                    flips[m].append({'run': r, 'why': why, 'band': i['band'], 'preselected': i['preselected'],
                                     'scanner': i.get('scanner'), 'target': i['target'],
                                     'in_truth': in_truth(osn, i['target'])})
            # L5: xtask's own verdict (exit 0 and "0 violation(s)") and the mirror here
            log = ''
            try:
                with open(os.path.join(r3, r, m + '.log'), encoding='utf-8', errors='replace') as f:
                    log = f.read()
            except OSError:
                pass
            said = [ln for ln in log.splitlines() if ': L5 against ' in ln]
            mirror = [(why, i['target']) for i in below if (why := stronger(no, i))]
            ok = rec['views'][m].get('exit') == 0 and len(said) == 1 and said[0].endswith(' 0 violation(s)') and not mirror
            l5_checked += 1
            if not ok:
                row('S4', 'S', f'L5 {m} {r}', f"exit {rec['views'][m].get('exit')}, xtask: {said[-1] if said else 'no L5 line'}, "
                    f'mirror: {len(mirror)} violation(s) {mirror[:3]}', 'l5_violations empty', False)
            b_off = offered(below)
            for k, i in ex_off.items():
                if i['target'].get('type') == 'RegKey' and k not in no_off:
                    w2[m][1] += 1
                    w2[m][0] += int(k in b_off and BANDS[b_off[k]['band']] >= BANDS['Likely'])
                w3[m][1] += 1
                w3[m][0] += int(k in no_off and k not in b_off)
    for m in BELOW:
        if runs:
            n = len(flips[m])
            row('S1', 'S', f'R3 {m} flips', f'{n} flip(s) over {judged} of {len(runs)} run(s); {listed_blocked[m]} new '
                f'item(s) listed Blocked only (reported)', '0 flips, every run judged', n == 0 and judged == len(runs))
            for f in flips[m][:50]:
                row('S1', 'S', f"flip {m} {f['run']}", f"{f['why']}: {f['scanner']} {f['band']}"
                    f"{' preselected' if f['preselected'] else ''} {f['target']} (in truth baseline: {f['in_truth']})",
                    'not more permissive than exact', False)
    row('S4', 'S', 'L5 over R3', f'{l5_checked} plan(s) below Exact checked', '>= 1, each empty', l5_checked > 0)

    # L3: exact plans byte-identical to the M1b gate's replay plans
    man = load(os.path.join(E['BL_L3_REF'], 'manifest.json'))
    refs = man.get('plans') if isinstance(man, dict) else None
    if not isinstance(refs, dict) or not refs:
        row('S4', 'S', 'L3', f"missing: {E['BL_L3_REF']}/manifest.json", 'reference plans', False)
    else:
        for rid, want in sorted(refs.items()):
            ref = os.path.join(E['BL_L3_REF'], rid + '.json')
            got = os.path.join(r3, rid, 'exact.json')
            if sha256(ref) != want:
                row('S4', 'S', f'L3 {rid}', f'reference {ref} missing or not sha256 {want[:12]}', 'pinned reference', False)
            elif rid not in runs or sha256(got) is None:
                row('S4', 'S', f'L3 {rid}', f'missing: {got}', 'exact plan replayed', False)
            else:
                row('S4', 'S', f'L3 {rid}', 'byte-identical' if sha256(got) == want else 'differs', 'byte-identical',
                    sha256(got) == want)

    # W2, W3 (merged judged; local reported)
    for m in BELOW:
        a, b = w2[m]
        row('W2', 'W' if m == 'merged' else 'report', f'R3 {m}', f'{a}/{b}' + (f' = {100 * a / b:.1f} %' if b else
            ' (no exact-only key candidate)'), '>= 80 % (below 50 %: presence-only)', bool(b) and a >= 0.8 * b)
        a, b = w3[m]
        row('W3', 'W' if m == 'merged' else 'report', f'R3 {m}', f'{a}/{b}' + (f' = {100 * a / b:.2f} %' if b else
            ' (exact offers nothing)'), '<= 1 %', bool(b) and a <= 0.01 * b)

    # R4: m1b.sh over the blm-/bll- campaigns
    sets = E['BL_R4_SETS'].split()
    for m in BELOW:
        p, rc = E.get(f'BL_R4_PREFIX_{m.upper()}', '?'), E.get(f'BL_R4_RC_{m.upper()}', '?')
        sc = load(os.path.join(OUT, f'r4-{m}', 'm1b-score.json'))
        crit = sc.get('criteria') if isinstance(sc, dict) else None
        if rc not in ('1', '3', 'collect-skipped') or not isinstance(crit, list):
            row('S1', 'S', f'R4 {m} ({p}-)', f'm1b.sh exit {rc}; score {"unreadable" if crit is None else "read"}',
                'm1b.sh exit 1 or 3 and a score', False)
            continue
        want_traps = E.get(f'BL_R4_TRAPS_{m.upper()}', '').split()
        if sc.get('sets') != sets or sc.get('trap_runs') != want_traps:
            row('S1', 'S', f'R4 {m} binding', f"sets {sc.get('sets')} trap runs {sc.get('trap_runs')}",
                f'sets {sets} trap runs {want_traps}', False)
        mine = [c for c in crit if isinstance(c, dict) and c.get('id') in ('RUN', 'K1', 'K2', 'K3', 'K9')]
        explained = {id(c) for c in mine if empty_plan_explained(m, p, c, mine)}
        for c in mine:
            if id(c) in explained:
                row('W3-R4', 'report', f"R4 {m} {c.get('id')} {c.get('subject')}", f"{c.get('value')}; the exact gate "
                    'offered only UFH\\SHC slot values, which no view below Exact offers (BL-FIX-UFH)',
                    'recall cost, reported (RUN ok, offered 0 and danger_listed 0, R3 replay offers nothing)', True)
            elif c.get('pass') is not True:
                row('S1', 'S', f"R4 {m} {c.get('id')} {c.get('subject')}", str(c.get('value')), str(c.get('limit')), False)
        k9 = [c for c in mine if c.get('id') == 'K9']
        danger = [c for c in mine if c.get('id') in ('K1', 'K2')]
        per_set = all(any(str(c.get('subject', '')).startswith(s + '/') for c in danger) for s in sets)
        good = [c.get('pass') is True or id(c) in explained for c in mine]
        row('S1', 'S', f'R4 {m} rows', f'{len(mine)} RUN/K1/K2/K3/K9 row(s), {sum(c.get("pass") is True for c in mine)} '
            f'pass, {len(explained)} empty plan(s) explained (W3-R4); {len(k9)} trap row(s)',
            'all pass, danger rows for every set, a trap row per set', bool(mine) and all(good) and len(k9) >= len(sets)
            and per_set)
        # danger_listed: not above the exact M1b gate run of the same set and app (design S1 says "= 0"; the exact gate
        # itself lists the deny-listed bam value Blocked, coordinator 2026-11-23); danger_offered: 0, literally
        for s in sets:
            got = load(os.path.join(OUT, f'r4-{m}', 'm1b-evidence', f'score-{s}.json'))
            ref = load(os.path.join(E['BL_EXACT_EVID'], f'score-{s}.json'))

            def field(doc, name):
                out = {}
                for a in (doc or {}).get('apps', []) if isinstance(doc, dict) else []:
                    for t in a.get('tools', []):
                        if t.get('tool') == 'purge':
                            out[a.get('id')] = t.get(name)
                return out
            g, x, o = field(got, 'danger_listed'), field(ref, 'danger_listed'), field(got, 'danger_offered')
            if not g:
                row('S1', 'S', f'R4 {m} {s} danger_listed', 'missing: score-' + s + '.json', 'per app', False)
            for app, n in sorted(g.items()):
                ok = isinstance(n, int) and isinstance(x.get(app), int) and n <= x[app]
                row('S1', 'S', f'R4 {m} {s}/{app} danger_listed', f'{n} (exact gate {x.get(app)})', '<= exact gate', ok)
                d = o.get(app)
                row('S1', 'S', f'R4 {m} {s}/{app} danger_offered', f'{d}', '0', d == 0)

    s_rows = [r for r in rows if r['kind'] == 'S']
    need = {('S1', 'R3'), ('S1', 'R4'), ('S4', 'L3'), ('S4', 'L5')}
    have = {(r['id'], r['subject'].split()[0]) for r in s_rows}
    for cid, what in sorted(need - have):
        row(cid, 'S', what, 'missing: no row was judged', 'judged', False)
        s_rows.append(rows[-1])
    ok = bool(s_rows) and all(r['pass'] for r in s_rows)
    for r in rows:
        verdict = ('PASS' if r['pass'] else 'FAIL') + ('' if r['kind'] == 'S' else f" ({r['kind']})")
        print(f"{r['id']} {r['subject']}: {r['value']} (limit {r['limit']}) {verdict}")
    print(f"bl: S criteria {'PASS' if ok else 'FAIL'} ({sum(not r['pass'] for r in s_rows)} failing S row(s))")
    os.makedirs(OUT, exist_ok=True)
    write(os.path.join(OUT, 'bl-score.json'), {'schema': 'purge.rig.bl-score/1', 'time': now(), 'pass': ok,
          'r3_summary': summ if isinstance(summ, dict) else None, 'rows': rows,
          'flips': flips, 'r4_collected': E.get('BL_R4_COLLECT') == '1'})
    sys.exit(0 if ok else 1)


# ------------------------------------------------------------------------------------------- self-test mutations
if MODE == 'mutate':  # mutate <fixture dir> <what> [path]
    d, what = A[0], A[1]
    J = lambda *p: os.path.join(d, *p)

    def edit(path, fn):
        doc = load(path)
        fn(doc)
        write(path, doc)
    if what == 'rm':
        os.remove(J(A[2]))
    elif what == 'garble':
        with open(J(A[2]), 'w', encoding='utf-8') as f:
            f.write('{"schema": "purge.plan/0", "items": [')
    elif what == 'flip':  # merged offers the value none offers and exact hides (Windows' own): L5 holds, S1 not
        edit(J('r3', 'm1bcp-7zip', 'merged.json'), lambda p: p['items'].append(load(J('r3', 'm1bcp-7zip', 'none.json'))['items'][0]))
    elif what == 'raise':  # local raises an item exact offers Weak
        def up(p):
            for i in p['items']:
                if i['band'] == 'Weak':
                    i['band'] = 'Likely'
        edit(J('r3', '7zip', 'local.json'), up)
    elif what == 'noruns':
        edit(J('r3', 'summary.json'), lambda s: s.update(runs=[]))
    elif what == 'l3':
        edit(J('r3', '7zip', 'exact.json'), lambda p: p.update(app='7zip '))
    elif what == 'l5':
        with open(J('r3', '7zip', 'merged.log'), 'a', encoding='utf-8') as f:
            f.write('replay: 7zip: L5 against none.json: 2 item(s) below Exact, 2 without a baseline, 1 violation(s)\n')
    elif what == 'trap':
        edit(J('r4-merged', 'm1b-score.json'), lambda s: [c.update(**{'pass': False}) for c in s['criteria'] if c['id'] == 'K9'])
    elif what == 'danger':
        edit(J('r4-local', 'm1b-evidence', 'score-clean.json'),
             lambda s: s['apps'][0]['tools'][0].update(danger_listed=2))
    elif what == 'offered':
        edit(J('r4-merged', 'm1b-evidence', 'score-clean.json'),
             lambda s: s['apps'][0]['tools'][0].update(danger_offered=1))
    elif what.startswith('empty'):
        # Merged clean/7zip plan empty with truth leftovers. 'emptyufh' sets up every condition of the R4 empty-plan
        # exception (bl_eval evaluate, empty_plan_explained); each other variant breaks exactly one of them.
        ufh = 'V:HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC|'
        items = [{'target': ufh + '1', 'band': 'Likely', 'outcome': 'hit'}]
        if what == 'emptyother':
            items = [{'target': 'V:HKU\\S-1-5-21-1\\Software\\7-Zip|Path', 'band': 'Likely', 'outcome': 'hit'}]
        elif what == 'emptymixed':
            items.append({'target': 'V:HKU\\S-1-5-21-1\\Software\\7-Zip|Path', 'band': 'Likely', 'outcome': 'hit'})
        edit(J('exact-evid', 'score-clean.json'), lambda s: s['apps'][0]['tools'][0].update(
            offered_n=len(items), items=items))
        edit(J('r4-merged', 'm1b-evidence', 'score-clean.json'), lambda s: s['apps'][0]['tools'][0].update(
            offered_n=0, danger_listed=1 if what == 'emptydanger' else 0))

        def empty(s):
            for c in s['criteria']:
                if c['id'] in ('K1', 'K3') and c['subject'] == 'clean/7zip':
                    c.update(value='empty plan: 0 items offered, 3 leftover/user-data truth item(s)',
                             limit='a plan with items', **{'pass': False})
                if c['id'] == 'RUN' and c['subject'] == 'blm-m1b-7zip' and what == 'emptyrunfail':
                    c.update(value='finished=False', **{'pass': False})
        edit(J('r4-merged', 'm1b-score.json'), empty)
        if what != 'emptynor3':
            os.makedirs(J('r3', 'm1b-7zip'), exist_ok=True)
            write(J('r3', 'm1b-7zip', 'merged.json'), {'schema': 'purge.plan/0', 'items': [
                {'target': {'type': 'RegValue', 'path': 'HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion'
                            '\\UFH\\SHC', 'name': '1'}, 'band': 'Blocked', 'preselected': False}]})
    else:
        sys.exit(1)
    sys.exit(0)

print(f'bl_eval: unknown mode {MODE}', file=sys.stderr)
sys.exit(2)
