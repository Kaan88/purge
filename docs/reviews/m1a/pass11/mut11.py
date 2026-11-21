"""Mutations of the tenth and eleventh pass. Works on a scratch copy of the tree (never the repository).
usage: mut10.py [name ...]"""
import os, subprocess, sys, shutil
HOME = os.path.expanduser('~')
P = HOME + '/purge-target/pass11'
WS = P + '/mutws'
REPO = '/mnt/C/Users/<user>/Desktop/uninstall/purge'
ENV = dict(os.environ, CARGO_TARGET_DIR=HOME + '/purge-target/pass11/tgt-mut', CARGO_BUILD_JOBS='8')
FW = 'crates/purge-scan/src/framework.rs'
PX = 'crates/purge-guard/src/prefix.rs'
REC = 'crates/purge-scan/src/ref_any/record.rs'
PIPE = 'bins/purge-engine/src/pipeline.rs'
RUN = 'crates/purge-scan/src/reg_run.rs'
HOST = 'crates/purge-scan/tests/reg/hostile.rs'
BAND = 'crates/purge-policy/src/band.rs'
APPD = 'crates/purge-scan/src/fs_appdata.rs'
APPP = 'crates/purge-scan/src/reg_apppaths.rs'
FEXT = 'crates/purge-scan/src/cls_fileexts.rs'
COMM = 'crates/purge-scan/src/reg_software.rs'
COLL = 'crates/purge-plan/src/collapse.rs'
PL = 'purge-plan'
S, G, E, PO = 'purge-scan', 'purge-guard', 'purge-engine', 'purge-policy'
M = [
 # the choke point, both layers
 ('C1-build-does-not-seal', FW, '        self.ctx.seal(&mut self.candidate);\n        self.candidate\n', '        self.candidate\n', [S, E]),
 ('C2-driver-does-not-seal', FW, '                None => self.seal(candidate),', '                None => (),', [S, E]),
 ('C3-pipeline-calls-scan', PIPE, 'let found = ctx.run(scanner.as_ref(), &app);', 'let found = scanner.scan(&ctx, &app);', [S, E]),
 ('C4-seal-never-caps', FW, 'if let Some(why) = self.content_unproven(&candidate.target) {', 'if let Some(why) = self.content_unproven(&candidate.target).filter(|_| false) {', [S, E]),
 # the rule
 ('R1-segment-not-judged', FW, '                let why = self.entry_unproven(segment)?;\n                (!self.named_after_app(name)).then_some(why)', '                let _ = (name, segment);\n                None', [S, E]),
 ('R2-value-not-judged', FW, 'Ok(data) => self.data_unproven(path, name, &data),', 'Ok(_) => None,', [S, E]),
 ('R3-unreadable-value-passes', FW, 'Err(_) => Some("the value could not be read"),', 'Err(_) => None,', [S, E]),
 ('R4-partial-data-passes', FW, '(!own).then_some("the data was not read in full")', 'None', [S, E]),
 ('R5-command-any-program', FW, '                    _ => Some("the command starts a program that is not the app\'s"),', '                    _ => None,', [S, E]),
 ('R6-command-folder-is-program', FW, 'Some(program) if !prefix::is_program_file(program) => {', 'Some(program) if false && !prefix::is_program_file(program) => {', [S, E]),
 ('R7-run-not-a-command-place', FW, '''        || (["Run", "RunOnce", "RunOnceEx"]
            .iter()
            .any(|run| prefix::eq_ci(leaf, run))
            && prefix::eq_ci(above, "CurrentVersion"))''', '', [S, E]),
 ('R8-verb-not-a-command-place', FW, 'prefix::eq_ci(leaf, "command")\n        ||', 'false\n        ||', [S, E]),
 ('R9-registration-any-text', FW, '(!is_software_key_path(whole))', '(false && !is_software_key_path(whole))', [S, E]),
 ('R10-list-entries-not-read', FW, '.find_map(|part| self.entry_unproven(resource_path(part)))', '.find_map(|_| None)', [S, E]),
 ('R11-own-place-list-not-read', FW, 'if own && !list {', 'if own {', [S, E]),
 ('R12-root-anchor-is-an-id', FW, 'm.how == MatchHow::Whole && !matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe)', 'm.how == MatchHow::Whole', [S, E]),
 ('R13-embedded-id-is-an-id', FW, 'm.how == MatchHow::Whole && !matches!', 'true && !matches!', [S, E]),
 ('R14-any-name-is-the-apps', FW, 'if self.entry_standing(name) == EntryStanding::Plain {\n            return true;', 'if true {\n            return true;', [S, E]),
 ('R15-ambiguous-entry-plain', FW, '        if read.ambiguous {', '        if false && read.ambiguous {', [S, E]),
 ('R16-indirect-entry-plain', FW, '        if read.indirect {', '        if false && read.indirect {', [S, E]),
 ('R17-any-path-is-own', FW, '''        if !own {
            return EntryStanding::Unproven("the entry is not a path of the app");''', '''        if false && !own {
            return EntryStanding::Unproven("the entry is not a path of the app");''', [S, E]),
 ('R18-not-one-path-plain', FW, '            return EntryStanding::NotOnePath;\n        };', '            return EntryStanding::Plain;\n        };', [S, E]),
 # places
 ('P1-vendor-wide-own-place', FW, '            || self.owns_place(key, false)\n    }', '            || self.owns_place(key, true)\n    }', [S, E]),
 ('P2-container-is-a-place', FW, '&& !purge_guard::containers::is_value_container(key, self.guard))', '&& true)', [S, E]),
 ('P3-key-record-not-a-place', FW, '''        (self.installer_recorded(key, None)
            && !purge_guard::containers::is_value_container(key, self.guard))
            || self.owns_place(key, false)''', '        self.owns_place(key, false)', [S, E]),
 ('P4-any-key-own-place', FW, '''        (self.installer_recorded(key, None)
            && !purge_guard::containers::is_value_container(key, self.guard))
            || self.owns_place(key, false)''', '        true', [S, E]),
 # reader
 ('X1-text-after-program-plain', PX, '                || text_after_program(text)\n', '', [G, S, E]),
 ('X2-any-file-is-a-program', PX, 'PROGRAM_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))', 'true', [G, S, E]),
 # scanners
 ('S1-record-evidence-after-build', REC, '''    b.evidence_also(snapshot);
    out.push(b.build());''', '''    let mut candidate = b.build();
    for evidence in snapshot {
        if !candidate.evidence.contains(&evidence) {
            candidate.evidence.push(evidence);
        }
    }
    out.push(candidate);''', [S, E]),
 ('S2-run-harvest-entry-not-read', RUN, '                && ctx.data_unproven(run_key, &entry.name, &recorded).is_none()\n', '', [S, E]),
 # pass eleven
 ('N1-path-with-forbidden-characters', PX, "!text.contains([';', '\"', '<', '>', '|', '?', '*'])", "!text.contains([';', '\"'])", [G, S, E]),
 ('N2-driver-seals-product-as-the-app', FW, 'Some(fp) => ScanCtx { fp, ..*self }.seal(candidate),', 'Some(_) => self.seal(candidate),', [S, E]),
 ('N3a-binary-runs-not-read', FW, '.find_map(|run| self.entry_unproven(resource_path(run.trim())))', '.find_map(|_| None)', [S, E]),
 ('N3b-large-binary-passes', FW, 'Some("the data is too large to be read for text")', 'None', [S, E]),
 ('N3c-every-run-is-judged', FW, '.filter(|run| is_path_shaped(run))', '.filter(|_| true)', [S, E]),
 ('N4-text-after-nul-not-seen', FW, '} else if string && data.has_text_after_nul() {', '} else if false && string && data.has_text_after_nul() {', [S, E]),
 ('N5a-name-with-text-after-the-path', FW, 'if self.entry_standing(name) == EntryStanding::Plain {', 'if self.entry_standing(name) != EntryStanding::NotOnePath {', [S, E]),
 ('N5b-name-exempts-in-command-places', FW, '(command || !self.named_after_app(name)).then_some(why)', '(!self.named_after_app(name)).then_some(why)', [S, E]),
 ('N7-token-anchor-tier-a', FW, 'AnchorKind::ProgId | AnchorKind::Clsid | AnchorKind::Aumid | AnchorKind::Token\n        ) && !self.manifest_covers_value();', 'AnchorKind::ProgId | AnchorKind::Clsid | AnchorKind::Aumid\n        ) && !self.manifest_covers_value();', [S, E]),
 ('N8a-no-product-folder-floor', BAND, '        || product_data_folder\n', '', [PO, E]),
 ('N8b-floor-for-any-category', BAND, 'let product_data_folder = c.category == Category::UserData', 'let product_data_folder = true', [PO, E]),
 ('N8c-floor-without-the-blocker', BAND, '&& c.blockers.iter().any(|b| matches!(b, Blocker::UserData))', '', [PO, E]),
 ('N8d-floor-for-keys', BAND, '        && matches!(c.target, Target::Path { .. })\n        && c.blockers', '        && c.blockers', [PO, E]),
 ('N8e-floor-on-ai-evidence', BAND, '                && e.tier != Tier::Ai\n                && effective_weight(e) > 0\n        })\n        && !c', '                && effective_weight(e) > 0\n        })\n        && !c', [PO, E]),
 ('N8f-floor-for-generic-names', BAND, '''        && !c
            .evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::GenericName);

    let mut notes''', ''';

    let mut notes''', [PO, E]),
 ('N8g-family-folder-not-kept', APPD, '            b.blocker(Blocker::ReferencedByOtherApp { app });\n        }\n        b.common_blockers();', '            let _ = app;\n        }\n        b.common_blockers();', [S]),
 ('N8h-family-name-for-any-folder', APPD, """            .any(|m| m.kind == EvidenceKind::ProductSubfolderOfVendor)
            .then(|| self.other_app_named(leaf))""", """            .any(|_| true)
            .then(|| self.other_app_named(leaf))""", [S]),
 ('N8i-any-other-app-shares-the-name', APPD, """            wanted
                .iter()
                .all(|t| theirs.contains(t))""", """            wanted
                .iter()
                .all(|t| theirs.contains(t) || true)""", [S]),
 ('B1-bare-name-with-a-foreign-path', APPP, 'if elsewhere || !product_name {', 'if !product_name {', [S]),
 ('B2-generic-bare-name', APPP, 'if elsewhere || !product_name {', 'if elsewhere {', [S]),
 ('B3-record-does-not-cover', APPP, 'if !recorded && other.is_none() && claimed.is_none() {', 'if other.is_none() && claimed.is_none() {', [S]),
 ('B3b-kept-key-is-dropped', APPP, 'if !recorded && other.is_none() && claimed.is_none() {', 'if !recorded {', [S]),
 ('B4-key-of-a-surviving-file', APPP, '} else if paths.iter().all(|path| outlived(ctx, path)) {', '} else if false {', [S]),
 ('B4b-present-file-of-an-installed-app', APPP, 'ctx.verify_gone_passed() && ctx.survived_unproven(path)', 'ctx.survived_unproven(path)', [S]),
 ('B5-openwithlist-not-resolved', FEXT, 'if crate::reg_apppaths::bare_name_leads_elsewhere(ctx, app, exe) {', 'if false {', [S]),
 ('B6-own-key-does-not-clear-the-name', APPP, 'if own.iter().any(|path| !outlived(ctx, path)) {\n            return false;', 'if false {\n            return false;', [S]),
 ('B7a-variable-path-is-no-path', COMM, ' || s.contains("%\\\\")', '', [S]),
 ('B7b-unc-path-is-no-path', COMM, ' || s.contains("\\\\\\\\") ||', ' ||', [S]),
 ('B7c-binary-path-is-no-path', APPP, '''            let elsewhere = !walk.complete
                || walk
                    .values
                    .iter()
                    .any(|(_, value)| common::names_a_path(value));''', '''            let elsewhere = !walk.complete
                || walk
                    .values
                    .iter()
                    .any(|(_, value)| value.data.string().is_some() && common::names_a_path(value));''', [S]),
 ('B8a-unticked-parent-not-checked', COLL, 'if !absorbing && !is_offered_whole(parent) {', 'if !absorbing {', [PL, E]),
 ('B8b-unticked-parent-gets-unmatched', COLL, 'if unmatched > 0 && absorbing {', 'if unmatched > 0 {', [PL, E]),
 ('B8d-objection-reported-twice', COLL, '''        blockers.retain(|new| {
            !parent.blockers.iter().any(|old| match (old, new) {
                (Blocker::UnmatchedChildren { .. }, Blocker::UnmatchedChildren { .. }) => true,
                _ => old == new,
            })
        });
''', '', [PL]),
 ('B8c-blocked-parent-checked-again', COLL, 'removes_whole(candidate) && band(candidate).is_some_and(|b| b != Band::Blocked)', 'removes_whole(candidate)', [PL, E]),
 ('T3-table-fingerprint-without-ids', HOST, 'fp.anchors.progids = vec![progid(), format!("FirefoxURL-{HASH}")];', 'fp.anchors.progids = Vec::new();', [S]),
 ('T4-table-without-the-aumid-place', HOST, 'fp.anchors.aumids = vec![aumid()];', 'fp.anchors.aumids = Vec::new();', [S]),
 # the table test itself
 ('T1-table-misses-a-registry-scanner', HOST, '    "CLS-REGAPPS",\n];', '    "CLS-REGAPPZ",\n];', [S]),
 ('T2-table-misses-a-file-scanner', HOST, '    "SYS-APPX",\n];', '    "SYS-APPY",\n];', [S]),
]
TIMEOUT = 900
def sh(cmd, log):
    """Runs cmd in its own process group; a run over TIMEOUT seconds is killed (group and wine children) and returns 'hung'."""
    import signal
    with open(log, 'w') as f:
        p = subprocess.Popen(cmd, shell=True, cwd=WS, env=ENV, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return p.wait(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            subprocess.run("pkill -9 -f 'tgt-mut/.*deps/.*\\.exe'", shell=True)
            p.wait()
            return 'hung'
def tests(pkgs, log):
    p = ' '.join('-p ' + x for x in pkgs)
    return sh(f'cargo test --target x86_64-pc-windows-gnullvm {p} --no-fail-fast -- --test-threads=8', log)
def counts(log):
    p = f = 0
    for l in open(log, errors='replace'):
        if l.startswith('test result:'):
            w = l.split(); p += int(w[3]); f += int(w[5])
    return p, f
only = sys.argv[1:]
os.makedirs(WS, exist_ok=True)
subprocess.run(f'rsync -a --delete {REPO}/crates/ {WS}/crates/ && rsync -a --delete {REPO}/bins/ {WS}/bins/ && mkdir -p {WS}/vm && rsync -a {REPO}/vm/truth {WS}/vm/ && rsync -a {REPO}/tools {REPO}/kb {REPO}/Cargo.toml {REPO}/Cargo.lock {REPO}/rust-toolchain.toml {REPO}/.cargo {WS}/', shell=True, check=True)
subprocess.run('find crates bins -name "*.rs" -exec touch {} +', shell=True, check=True, cwd=WS)
if not only:
    rc = tests([G, S, E, PO, PL], P + '/mut11-baseline.log')
    print('BASELINE rc', rc, 'passed/failed', counts(P + '/mut11-baseline.log'), flush=True)
    if rc != 0:
        sys.exit('baseline is not clean')
killed = 0; total = 0
for name, path, a, b, pkgs in M:
    if only and name not in only: continue
    total += 1
    full = os.path.join(WS, path)
    src = open(full, encoding='utf-8').read()
    if src.count(a) != 1:
        print(name, 'NOT APPLIED (count %d)' % src.count(a), flush=True); continue
    open(full, 'w', encoding='utf-8').write(src.replace(a, b))
    log = f'{P}/mut11-{name}.log'
    rc = tests(pkgs, log)
    p, f = counts(log)
    compiled = 'error: could not compile' not in open(log, errors='replace').read()
    failing = [l.split()[1] for l in open(log, errors='replace') if l.startswith('test ') and l.rstrip().endswith('FAILED')]
    verdict = 'HUNG' if rc == 'hung' else 'KILLED' if (rc != 0 and compiled and f > 0) else ('BUILD-ERROR' if not compiled else 'SURVIVED')
    killed += verdict in ('KILLED', 'HUNG')
    print(name, verdict, f'passed {p} failed {f}', ' '.join(sorted(set(failing))[:6]), flush=True)
    open(full, 'w', encoding='utf-8').write(src)
print(f'{killed} of {total} killed')
