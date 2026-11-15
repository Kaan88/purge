"""Mutation run on Windows: the table of mut11.py, brought up to the tree after the eleventh review,
plus mutations of that review's fixes. Works on a scratch copy of the tree (never the repository).

usage: python -I mutwin.py <repo> <scratch dir> [name ...]
"""
import os
import shutil
import subprocess
import sys

REPO, P = sys.argv[1], sys.argv[2]
only = sys.argv[3:]
WS = os.path.join(P, 'mutws')
src = open(os.path.join(REPO, 'docs/reviews/m1a/pass11/mut11.py'), encoding='utf-8').read()
ns = {'os': os}
exec(src[src.index('FW = '):src.index('TIMEOUT = 900')], ns)
FW, PX, APPP, COMM, COLL = ns['FW'], ns['PX'], ns['APPP'], ns['COMM'], ns['COLL']
S, G, E, PL = ns['S'], ns['G'], ns['E'], ns['PL']
MATCHER = 'crates/purge-index/src/matcher.rs'

OWN_PLACE = r'''        (self.installer_recorded(key, None)
            && !purge_guard::containers::is_value_container(key, self.guard)
            && !is_start_place(key))
            || self.owns_place(key, false)'''

# Entries of mut11.py whose source text changed after the eleventh review: same mutation, new text.
OVERRIDES = {
    'R7-run-not-a-command-place': (FW, r'''    (["Run", "RunOnce", "RunServices", "RunServicesOnce"]
        .iter()
        .any(|run| prefix::eq_ci(leaf, run))
        && prefix::eq_ci(above, "CurrentVersion"))
        || (prefix::eq_ci(leaf, "Run")''', r'''    (false && prefix::eq_ci(above, "CurrentVersion"))
        || (prefix::eq_ci(leaf, "Run")''', [S, E]),
    'R8-verb-not-a-command-place': (FW, r'''prefix::leaf(key).is_some_and(|leaf| prefix::eq_ci(leaf, "command")) || is_start_place(key)''',
                                    r'''is_start_place(key)''', [S, E]),
    'P2-container-is-a-place': (FW, r'''
            && !purge_guard::containers::is_value_container(key, self.guard)
            && !is_start_place(key))''', r'''
            && !is_start_place(key))''', [S, E]),
    'P3-key-record-not-a-place': (FW, OWN_PLACE, '        self.owns_place(key, false)', [S, E]),
    'P4-any-key-own-place': (FW, OWN_PLACE, '        true', [S, E]),
    'B4b-present-file-of-an-installed-app': (
        APPP, r'''programs_gone && ctx.survived_unproven(path)''', r'''ctx.survived_unproven(path)''', [S]),
    'B6-own-key-does-not-clear-the-name': (
        APPP, r'''if walk.complete && own.iter().any(|path| !outlived(ctx, path)) {
            continue;''', r'''if false {
            continue;''', [S]),
}

# The eleventh review's fixes and the test gaps it named.
EXTRA = [
    ('V1-start-place-own-by-record', FW, r'''
            && !is_start_place(key))''', r''')''', [S, E]),
    ('V2-policies-run-not-a-start-place', FW, r'''        || (prefix::eq_ci(leaf, "Run")
            && prefix::eq_ci(above, "Explorer")
            && prefix::eq_ci(third, "Policies"))
''', '', [S, E]),
    ('V3-runonceex-not-a-start-place', FW,
     r'''prefix::eq_ci(pair[0], "CurrentVersion") && prefix::eq_ci(pair[1], "RunOnceEx")''', 'false', [S, E]),
    ('V4-runservices-not-a-start-place', FW, r'''["Run", "RunOnce", "RunServices", "RunServicesOnce"]''',
     r'''["Run", "RunOnce"]''', [S, E]),
    ('V5-number-by-type-tag', FW, r'''let number = data.dword().is_some() || data.qword().is_some();''',
     r'''let number = matches!(data.ty, 4 | 5 | 11);''', [S, E]),
    ('V6-ansi-text-not-read', FW, r'''    runs.extend(
        ansi_runs(&data.bytes)
            .into_iter()
            .filter(|run| holds_drive_or_unc_path(run)),
    );
''', '', [S, E]),
    ('V7-variable-not-path-shaped', FW, r''' || run.matches('%').count() >= 2''', '', [S, E]),
    ('V8-only-drive-paths-are-path-shaped', FW, r'''run.contains(['\\', '/']) || ''',
     r'''run.contains(":\\") || ''', [S, E]),
    ('V9-any-name-with-an-id', FW, r'''is_id_shaped(name)
            && ''', '', [S, E]),
    ('V10-unreadable-command-excused-by-name', FW,
     r'''(!is_command_place(path) && self.named_after_app(name))''', r'''self.named_after_app(name)''', [S, E]),
    ('V11-first-hive-answers-for-all', APPP, r'''if walk.complete && own.iter().any(|path| !outlived(ctx, path)) {
            continue;''', r'''if walk.complete && own.iter().any(|path| !outlived(ctx, path)) {
            return false;''', [S]),
    ('V12-unread-key-leads-nowhere', APPP, r'''        elsewhere |= !walk.complete
            || !own.is_empty()''', r'''        elsewhere |= !own.is_empty()''', [S]),
    ('V13-unread-key-with-an-own-path-is-the-apps', APPP,
     r'''if walk.complete && own.iter().any(|path| !outlived(ctx, path)) {
            continue;''', r'''if own.iter().any(|path| !outlived(ctx, path)) {
            continue;''', [S]),
    ('V14-large-binary-names-no-path', COMM, r'''
            || (!text_type && data.bytes.len() > BINARY_UTF16_SCAN_MAX)''', '', [S]),
    ('V15-text-after-the-end-names-no-path', COMM, r'''
            || (data.string().is_some() && data.has_text_after_nul())''', '', [S]),
    ('V16-incomplete-data-names-no-path', COMM, r'''        !data.is_complete()
            || (!text_type''', r'''        (!text_type''', [S]),
    ('V17-bare-name-unread-key-is-offered', APPP, r'''let elsewhere = !walk.complete
                || walk''', r'''let elsewhere = walk''', [S]),
    ('V18-separator-not-path-shaped', FW, r'''run.contains(['\\', '/']) || ''', '', [S, E]),
    ('V19-contained-other-app-is-no-objection', COLL, r'''
                | Blocker::ContainsOtherApp { app } => Some(app.clone()),''', r''' => Some(app.clone()),''', [PL]),
    ('V20-msi-owner-is-no-objection', COLL,
     r'''                Blocker::OwnedByInstalledMsi { product, .. } => Some(product.clone()),
''', '', [PL]),
    ('V21-only-likely-parents-are-offered', COLL,
     r'''removes_whole(candidate) && band(candidate).is_some_and(|b| b != Band::Blocked)''',
     r'''removes_whole(candidate) && band(candidate) == Some(Band::Likely)''', [PL]),
    ('V22-kelvin-sign-folds-to-k', PX, r'''        (None, Some(c))
    };''', r'''        (Some(c.to_lowercase()), None)
    };''', [G]),
    ('V23-surviving-file-rule-needs-the-whole-check', APPP,
     r'''v.is_passed() || (v.main_exes_gone && ctx.fp.main_exes().next().is_some())''', r'''v.is_passed()''', [S]),
    ('V24-no-main-exe-counts-as-gone', APPP,
     r'''(v.main_exes_gone && ctx.fp.main_exes().next().is_some())''', r'''v.main_exes_gone''', [S]),
    ('V25-any-separator-in-8-bit-text', FW, r'''.filter(|run| holds_drive_or_unc_path(run))''',
     r'''.filter(|run| is_path_shaped(run))''', [S, E]),
    ('V26-high-bytes-are-text', FW, r'''.split(|b| !(0x20..=0x7e).contains(b))''',
     r'''.split(|b| *b < 0x20 || *b == 0x7f)''', [S, E]),
    ('V27-folds-above-the-bmp', PX, r'''let apart = code > 0xFFFF
        || WINDOWS_KEEPS_APART''', r'''let apart = WINDOWS_KEEPS_APART''', [G]),
    ('V28-folds-what-windows-keeps-apart', PX, r'''.any(|(first, last)| (*first..=*last).contains(&code));''',
     r'''.any(|(first, last)| first > last);''', [G]),
]

M = [(n, *OVERRIDES[n]) if n in OVERRIDES else (n, p, a, b, k) for n, p, a, b, k in ns['M']] + EXTRA
ENV = dict(os.environ, CARGO_TARGET_DIR=os.path.join(P, 'tgt-mut'))
TIMEOUT = 900


def sh(cmd, log):
    with open(log, 'w') as f:
        p = subprocess.Popen(cmd, cwd=WS, env=ENV, stdout=f, stderr=subprocess.STDOUT)
        try:
            return p.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            subprocess.run(['taskkill', '/T', '/F', '/PID', str(p.pid)], capture_output=True)
            p.wait()
            return 'hung'


def tests(pkgs, log):
    cmd = ['cargo', 'test']
    for x in pkgs:
        cmd += ['-p', x]
    return sh(cmd + ['--no-fail-fast'], log)


def counts(log):
    p = f = 0
    for line in open(log, errors='replace'):
        if line.startswith('test result:'):
            w = line.split()
            p += int(w[3])
            f += int(w[5])
    return p, f


os.makedirs(WS, exist_ok=True)
for d in ('crates', 'bins', 'tools', 'kb', '.cargo', 'vm/truth'):
    s = os.path.join(REPO, d)
    if os.path.isdir(s):
        subprocess.run(['robocopy', s, os.path.join(WS, d), '/MIR', '/NFL', '/NDL', '/NJH', '/NJS', '/NP',
                        '/XD', 'target'], capture_output=True)
for f in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'):
    shutil.copy2(os.path.join(REPO, f), os.path.join(WS, f))
if not only:
    base = os.path.join(P, 'mut-baseline.log')
    rc = tests([G, S, E, ns['PO'], PL], base)
    print('BASELINE rc', rc, 'passed/failed', counts(base), flush=True)
    if rc != 0:
        sys.exit('baseline is not clean')
killed = total = 0
for name, path, a, b, pkgs in M:
    if only and name not in only:
        continue
    total += 1
    full = os.path.join(WS, path)
    text = open(full, encoding='utf-8', newline='').read().replace(chr(13) + chr(10), chr(10))
    if text.count(a) != 1:
        print(name, 'NOT APPLIED (count %d)' % text.count(a), flush=True)
        continue
    open(full, 'w', encoding='utf-8', newline='').write(text.replace(a, b))
    log = os.path.join(P, f'mut-{name}.log')
    rc = tests(pkgs, log)
    p, f = counts(log)
    body = open(log, errors='replace').read()
    compiled = 'error: could not compile' not in body
    failing = [line.split()[1] for line in body.splitlines()
               if line.startswith('test ') and line.rstrip().endswith('FAILED')]
    verdict = ('HUNG' if rc == 'hung' else 'KILLED' if (rc != 0 and compiled and f > 0)
               else 'BUILD-ERROR' if not compiled else 'SURVIVED')
    killed += verdict in ('KILLED', 'HUNG')
    print(name, verdict, f'passed {p} failed {f}', ' '.join(sorted(set(failing))[:6]), flush=True)
    open(full, 'w', encoding='utf-8', newline='').write(text)
print(f'{killed} of {total} killed')
