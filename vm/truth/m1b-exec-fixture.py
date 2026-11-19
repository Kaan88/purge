"""Synthetic m1b-x-* run sets for the m1b-exec.sh self-test (review R4 S7; vm/rig-m1b-exec.ps1 -Mode m1b-x-selftest).

    python -I vm/truth/m1b-exec-fixture.py --cases vm/truth/m1b-exec-cases.json --out <dir> [--mutate <name>]

Writes <dir>/cases.json (the cases file, edited by a cases-* mutation), <dir>/ambient.json (an M1b exec ambient set
of NULL_RUNS null runs per null mode, edited by an ambient-* file mutation) and <dir>/runs/m1b-x-*/ as the guest and
host would for a run in which every criterion holds, built from that cases file (not from the scorer's constants),
then applies one named mutation that makes the run set bad. The self-test scores each set with
M1B_RUNS=<dir>/runs M1B_CASES=<dir>/cases.json M1B_AMBIENT=<dir>/ambient.json and requires: no mutation -> PASS;
every mutation -> FAIL on the criterion it names (MUTATIONS). An unknown mutation name is an error (exit 2), never a
passing set.
"""
import argparse, copy, hashlib, json, os, sys

KINDS = ["service", "task", "firewall"]
ENGINE = "ab" * 32
COMMIT = "0123456789abcdef0123456789abcdef01234567"
NULL_RUNS = 6                                                             # per null mode (m1b-exec.sh MIN_NULL_RUNS_PER_MODE)
GUEST_AMBIENT = "C:\\cr\\bin\\m2-ambient.json"

# name -> (criterion the score must fail, what the mutation does)
MUTATIONS = {
    "collateral": ("K10", "the fidelity execdiff reports one collateral record"),
    "unexplained": ("K10", "the fidelity execdiff reports one added record nothing authorises (R4 S2)"),
    "crash-unexplained": ("K13", "an exec/resume crash round's execdiff has one unexplained record (R4 S2)"),
    "full-not-restored": ("K11", "a full variant's undo is not Restored"),
    "trap-deleted": ("K12", "a changed act-time trap object was deleted"),
    "svc-running-restarted": ("K12", "the running service has another PID after exec (R4 S3)"),
    "svc-running-stopped": ("K12", "the running service is stopped after exec (R4 S3)"),
    "twin-base-not-done": ("K12", "the same-name twin case: the planned rule was skipped, not deleted (R4 S5)"),
    "twin-changed": ("K12", "the same-name twin changed"),
    "impostor-overwritten": ("K12", "an undo impostor was overwritten"),
    "unreached-point": ("K13", "one crash round did not hit its point"),
    "repeat-hides-failure": ("K13", "a crash round ran twice, the first failed (R4 M7)"),
    "poweroff-14": ("K13", "14 power-off rounds instead of 15"),
    "poweroff-not-mid-run": ("K13", "a power-off round's journal shows the run had committed before the cut (R4 S1)"),
    "poweroff-repeated-point": ("K13", "a kind's five power-off rounds repeat a point"),
    "cases-min-full": ("K11", "cases min_full 0 and a full task variant relabelled refused (R4 S4)"),
    "cases-drop-trap": ("K12", "cases and runs without the svc-running trap (R4 S4)"),
    "cases-drop-point": ("K13", "cases move act.after to not_reachable; no round runs it (R4 S4)"),
    "cases-fewer-poweroff": ("K13", "cases rounds_per_kind 4; 12 power-off rounds (R4 S4)"),
    "cases-elevated-min": ("E1", "cases lower the scm test minimum and the run has fewer tests (R4 S4)"),
    "cases-sha": ("BIND", "the traps run got another cases file (R4 S4)"),
    "engine-differs": ("BIND", "the crash run ran another engine (R4 S6)"),
    "engine-installed-differs": ("BIND", "the installed engine is not the staged one (R4 S6)"),
    "commit-differs": ("BIND", "the elevated run names another commit (R4 S6)"),
    "source-dirty": ("BIND", "the fidelity run's sources were dirty (R4 S6)"),
    "ambient-missing-in-run": ("BIND", "the crash run records no ambient set (R8 S3)"),
    "ambient-other-hash": ("BIND", "the traps run declared and used another ambient set (R8 S3)"),
    "ambient-guest-differs": ("BIND", "the undo-traps run's guest copy differs from the declared set (R8 S3)"),
    "ambient-declared-missing": ("BIND", "the fidelity run's host declared no ambient set (R8 S3)"),
    "ambient-few-null-runs": ("BIND", "the committed set holds 5 null runs of m1b-x-traps (R8 S3)"),
    "ambient-gate-run-id": ("BIND", "the committed set was built from a gate run m1b-x-fidelity (R8 S2, S3)"),
    "ambient-fixture-name": ("BIND", "the committed set names a PurgeExec* service (R8 S2, S3)"),
    "ambient-schema": ("BIND", "the committed set has another schema (R8 S3)"),
}

# Mutations of the ambient file itself (applied before it is hashed: the runs then name the mutated file's hash, so
# only the file check can catch them).
AMBIENT_FILE_MUTATIONS = {"ambient-few-null-runs", "ambient-gate-run-id", "ambient-fixture-name", "ambient-schema"}


def write(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)


def st(present=True, tag="x"):
    return {"present": present, "sha256": hashlib.sha256(tag.encode()).hexdigest() if present else None}


def phases():
    return [{"name": "p", "ok": True}]


def ambient_doc():
    runs = []
    for k in range(1, NULL_RUNS + 1):
        for m in ("m1b-x-fidelity", "m1b-x-traps"):
            rid = "xn%d-%s" % (k, m)
            runs.append({"id": rid, "dir": "runs\\" + rid, "pair": ["snap-%s-a.tsv.gz" % rid, "snap-%s-b.tsv.gz" % rid],
                         "records": ["~K:HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\CIMWin32 @ root/CIMV2"],
                         "patterns": []})
    return {"schema": "purge.rig.m2ambient/1", "note": "fixture", "runs": runs,
            "records": ["~K:HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\CIMWin32 @ root/CIMV2"],
            "patterns": ["(?i)^~V:HKLM\\\\SOFTWARE\\\\X\\|[0-9]+$"]}


def mutate_ambient(a, m):
    if m == "ambient-few-null-runs":
        a["runs"] = [r for r in a["runs"] if r["id"] != "xn%d-m1b-x-traps" % NULL_RUNS]
    elif m == "ambient-gate-run-id":
        a["runs"][0]["id"] = "m1b-x-fidelity"
    elif m == "ambient-fixture-name":
        a["records"].append("~K:HKLM\\SYSTEM\\CurrentControlSet\\Services\\PurgeExecSvcA")
    elif m == "ambient-schema":
        a["schema"] = "purge.rig.ambient/1"


def run_doc(mode, cases_sha, results, engine=ENGINE, installed=None, commit=COMMIT, dirty=False, amb_sha=None):
    r = {"cases": {"sha256": cases_sha},
         "engine_build": {"declared": {"sha256": engine, "commit": commit, "source_dirty": dirty},
                          "staged_sha256": engine, "installed_sha256": installed or engine},
         "ambient": {"declared": {"file": "vm\\truth\\m1b-exec-ambient.json", "sha256": amb_sha}, "guest": GUEST_AMBIENT,
                     "guest_sha256": amb_sha}}
    r.update(results)
    return {"schema": "purge.rig.m2/1", "run": mode, "mode": mode, "finished": "2026-11-17T00:00:00Z", "phases": phases(), "results": r}


def point_phases(cases, fp):
    out = []
    dflt = lambda ph: (cases["crash"]["undo_afters"] if ph == "undo" else cases["crash"]["exec_afters"])
    if fp.get("phase"):
        out.append((fp["phase"], dflt(fp["phase"])))
    for m in fp.get("more_phases") or []:
        if m.get("phase"):
            out.append((m["phase"], m.get("afters") or dflt(m["phase"])))
    return out


def crash_row(n, kind, point, phase, after, rkind="abort"):
    r = {"n": n, "kind": rkind, "object_kind": kind, "point": point, "phase": phase, "after": after,
         "tag": "c%03d-%s-%s-%s-%s" % (n, kind, phase, point, after), "hit": True, "crashed": True, "error": None,
         "recover_exit": 0, "recover2_exit": 0, "recover_idempotent": True, "after_exit": 0, "fidelity_ok": True,
         "object_restored": True, "execdiff_ok": None, "execdiff_unexplained": None, "undo_exit": None,
         "undone_by_recovery": None, "boot_changed": None, "pfro_unchanged": None, "cut_mid_run": None, "pass": True}
    if phase == "exec" and after == "resume":
        r.update({"execdiff_ok": True, "execdiff_unexplained": 0, "execdiff_collateral": 0, "undo_exit": 0})
    if phase == "undo":
        r["undone_by_recovery"] = True
    if rkind == "poweroff":
        r.update({"boot_changed": True, "pfro_unchanged": True, "cut_mid_run": True,
                  "cut": {"ok": True, "facts": {"commit": False, "open_intents": ["1"]}}})
    return r


def build(cases, cases_sha, mutate, amb_sha):
    sets = {}
    ex = lambda ok=True, c=0, u=0: {"ok": ok, "counts": {"collateral": c, "guard_escapes": 0, "unexplained": u, "missing_effects": 0, "changed_not_done": 0},
                                    "inputs": {"ambient": "C:\\cr\\m2-ambient.json"}}
    # m1b-x-fidelity
    variants, ops = [], []
    for i, v in enumerate(cases["fidelity"]["variants"], 1):
        p = st(True, v["id"])
        if v["expect"] == "full":
            g = {"id": v["id"], "kind": v["kind"], "recorded": True, "planted": p, "offered": {"id": "c%d" % i, "band": "Safe"},
                 "selected": True, "exec": {"kind": "Done", "op": i}, "after_exec": st(False), "undo": {"result": "Finished", "kind": "Restored"},
                 "after_undo": p}
            ops.append({"id": i, "objects": 3, "differing": 0})
        else:
            g = {"id": v["id"], "kind": v["kind"], "recorded": True, "planted": p, "offered": {"id": "c%d" % i, "band": "Blocked"},
                 "selected": False, "exec": {}, "after_exec": p, "undo": {}, "after_undo": p}
        variants.append(g)
    fid = run_doc("m1b-x-fidelity", cases_sha, {"variants": variants, "execs": {"main": {"exit": 0}}, "undo": {"main": {"exit": 0}}}, amb_sha=amb_sha)
    sets["m1b-x-fidelity/run.json"] = fid
    sets["m1b-x-fidelity/execdiff-main.json"] = ex()
    sets["m1b-x-fidelity/fidelity-main.json"] = {"ok": True, "ops": ops, "rows": [], "normalisations": []}
    # m1b-x-traps
    traps = []
    for t in cases["act_traps"]["cases"]:
        g = {"id": t["id"], "kind": t["kind"], "change": t["change"], "changed": True}
        if t["expect"] == "twin-untouched":
            g.update({"exec": {"kind": "Done"}, "after_exec": st(False), "twin_before": st(True, "twin"), "twin_after": st(True, "twin")})
        else:
            g.update({"exec": {"kind": "Skipped", "reason": "GateBlocked", "blocker": t.get("blocker") or "ObjectChanged"},
                      "after_change": st(True, t["id"]), "after_exec": st(True, t["id"])})
            if t["change"] == "start":
                g["scm_after_change"] = {"state": "Running", "pid": 4242}
                g["scm_after_exec"] = {"state": "Running", "pid": 4242}
        traps.append(g)
    sets["m1b-x-traps/run.json"] = run_doc("m1b-x-traps", cases_sha, {"act_traps": traps, "execs": {"traps": {"exit": 10}}}, amb_sha=amb_sha)
    sets["m1b-x-traps/execdiff-traps.json"] = ex()
    # m1b-x-undo-traps
    uts = []
    for t in cases["undo_traps"]["cases"]:
        g = {"id": t["id"], "variant": t["variant"], "trap": t["trap"], "set": True, "undo": {"result": "Conflict", "kind": t["expect_conflict"]}}
        if t["trap"].startswith("impostor"):
            g.update({"before_undo": st(True, "imp"), "after_undo": st(True, "imp")})
        elif t["trap"] == "tamper-definition":
            g.update({"after_undo": st(False), "definition_sha_after_trap": "AA", "definition_sha_after_undo": "AA"})
        else:
            g.update({"after_undo": st(False), "definition_present_after_undo": False})
        uts.append(g)
    sets["m1b-x-undo-traps/run.json"] = run_doc("m1b-x-undo-traps", cases_sha, {"undo_traps": uts, "undo": {"main": {"exit": 11}}}, amb_sha=amb_sha)
    # m1b-x-crash
    rows, n = [], 0
    for k in KINDS:
        for fp in cases["crash"]["fault_points"]:
            if k not in (fp.get("kinds") or []):
                continue
            for ph, afters in point_phases(cases, fp):
                for a in afters:
                    n += 1
                    rows.append(crash_row(n, k, fp["point"], ph, a))
    per = int(cases["crash"]["poweroff"]["rounds_per_kind"])
    for k in KINDS:
        for p in cases["crash"]["poweroff"]["pool"][k][:per]:
            n += 1
            rows.append(crash_row(n, k, p["point"], p["phase"], "resume", "poweroff"))
    declared = [fp["point"] for fp in cases["crash"]["fault_points"]]
    sets["m1b-x-crash/run.json"] = run_doc("m1b-x-crash", cases_sha, {"fault_points": {"declared": declared}}, amb_sha=amb_sha)
    sets["m1b-x-crash/crash-matrix.json"] = {"schema": "purge.rig.m1b-crashmatrix/1", "points": declared, "kinds": [], "filter_points": [], "rows": rows}
    # m1b-x-elevated
    targets = []
    for t in cases["elevated"]["targets"]:
        if t.get("run") == "all":
            names = ["%s%s_%d" % (t.get("require_prefix") or "", t["test"], i) for i in range(int(t["min"]))]
        else:
            names = ["tests::" + x for x in t["require_names"]]
        targets.append({"crate": t["crate"], "test": t["test"], "exit": 0, "tests": [{"name": x, "result": "ok"} for x in names]})
    sets["m1b-x-elevated/elevated-tests.json"] = {"schema": "purge.rig.m1b-elevated/1", "admin": True, "targets": targets,
                                                 "cases_sha256": cases_sha, "build": {"commit": COMMIT, "source_dirty": False}, "pass": True}
    return sets


def mutate_cases(cases, m):
    c = copy.deepcopy(cases)
    if m == "cases-min-full":
        c["fidelity"]["min_full"] = {"service": 0, "task": 0, "firewall": 0}
        for v in c["fidelity"]["variants"]:
            if v["id"] == "task-com":
                v["expect"] = "refused"
    elif m == "cases-drop-trap":
        c["act_traps"]["cases"] = [t for t in c["act_traps"]["cases"] if t["id"] != "svc-running"]
    elif m == "cases-drop-point":
        for fp in c["crash"]["fault_points"]:
            if fp["point"] == "act.after":
                fp["phase"], fp["kinds"] = None, []
                fp["not_reachable"] = {k: "moved out by the self-test" for k in KINDS}
    elif m == "cases-fewer-poweroff":
        c["crash"]["poweroff"]["rounds_per_kind"] = 4
    elif m == "cases-elevated-min":
        for t in c["elevated"]["targets"]:
            if t["test"] == "scm":
                t["min"] = 3
                t["prefix_min"] = 1
    return c


def mutate_sets(s, m):
    fid = s["m1b-x-fidelity/run.json"]["results"]
    trp = {t["id"]: t for t in s["m1b-x-traps/run.json"]["results"]["act_traps"]}
    rows = s["m1b-x-crash/crash-matrix.json"]["rows"]
    po = [r for r in rows if r["kind"] == "poweroff"]
    if m == "collateral":
        s["m1b-x-fidelity/execdiff-main.json"]["counts"]["collateral"] = 1
        s["m1b-x-fidelity/execdiff-main.json"]["ok"] = False
    elif m == "unexplained":
        s["m1b-x-fidelity/execdiff-main.json"]["counts"]["unexplained"] = 1      # ok stays true: rigtool does not fail it
    elif m == "crash-unexplained":
        r = next(r for r in rows if r["kind"] == "abort" and r["phase"] == "exec" and r["after"] == "resume")
        r["execdiff_unexplained"] = 1
    elif m == "full-not-restored":
        v = next(v for v in fid["variants"] if v["undo"].get("result") == "Finished")
        v["undo"]["kind"] = "Partial"
    elif m == "trap-deleted":
        trp["svc-repoint"]["after_exec"] = st(False)
    elif m == "svc-running-restarted":
        trp["svc-running"]["scm_after_exec"]["pid"] = 5000
    elif m == "svc-running-stopped":
        trp["svc-running"]["scm_after_exec"] = {"state": "Stopped", "pid": 0}
    elif m == "twin-base-not-done":
        t = trp["fw-same-name"]
        t["exec"] = {"kind": "Skipped", "reason": "ChangedSinceScan"}
        t["after_exec"] = st(True, "base")
    elif m == "twin-changed":
        trp["fw-same-name"]["twin_after"] = st(True, "other")
    elif m == "impostor-overwritten":
        s["m1b-x-undo-traps/run.json"]["results"]["undo_traps"][0]["after_undo"] = st(True, "recreated")
    elif m == "unreached-point":
        r = next(r for r in rows if r["point"] == "objdelete.after" and r["kind"] == "abort")
        r["hit"] = False
    elif m == "repeat-hides-failure":
        r = next(r for r in rows if r["point"] == "commit.before" and r["kind"] == "abort")
        bad = dict(r, fidelity_ok=False)
        rows.insert(rows.index(r), bad)
    elif m == "poweroff-14":
        rows.remove(po[-1])
    elif m == "poweroff-not-mid-run":
        po[1]["cut_mid_run"] = False                                            # hit left true: the score must look itself
        po[1]["cut"] = {"ok": False, "facts": {"commit": True, "open_intents": []}}
    elif m == "poweroff-repeated-point":
        k = po[0]["object_kind"]
        same = [r for r in po if r["object_kind"] == k]
        same[2]["point"], same[2]["phase"] = same[1]["point"], same[1]["phase"]
    elif m == "cases-sha":
        s["m1b-x-traps/run.json"]["results"]["cases"]["sha256"] = "00" * 32
    elif m == "engine-differs":
        b = s["m1b-x-crash/run.json"]["results"]["engine_build"]
        b["declared"]["sha256"] = b["staged_sha256"] = b["installed_sha256"] = "cd" * 32
    elif m == "engine-installed-differs":
        s["m1b-x-undo-traps/run.json"]["results"]["engine_build"]["installed_sha256"] = "ef" * 32
    elif m == "commit-differs":
        s["m1b-x-elevated/elevated-tests.json"]["build"]["commit"] = "f" * 40
    elif m == "source-dirty":
        s["m1b-x-fidelity/run.json"]["results"]["engine_build"]["declared"]["source_dirty"] = True
    elif m == "ambient-missing-in-run":
        del s["m1b-x-crash/run.json"]["results"]["ambient"]
    elif m == "ambient-other-hash":
        a = s["m1b-x-traps/run.json"]["results"]["ambient"]
        a["declared"]["sha256"] = a["guest_sha256"] = "12" * 32
    elif m == "ambient-guest-differs":
        s["m1b-x-undo-traps/run.json"]["results"]["ambient"]["guest_sha256"] = "34" * 32
    elif m == "ambient-declared-missing":
        s["m1b-x-fidelity/run.json"]["results"]["ambient"]["declared"] = None
    elif m == "cases-elevated-min":
        for t in s["m1b-x-elevated/elevated-tests.json"]["targets"]:
            if t["test"] == "scm":
                t["tests"] = t["tests"][:3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mutate", default="")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for k, (crit, what) in MUTATIONS.items():
            print("%s\t%s\t%s" % (k, crit, what))
        return 0
    if a.mutate and a.mutate not in MUTATIONS:
        print("unknown mutation %s" % a.mutate, file=sys.stderr)
        return 2
    with open(a.cases, "r", encoding="utf-8-sig") as f:
        cases = json.load(f)
    if a.mutate.startswith("cases-") and a.mutate != "cases-sha":
        cases = mutate_cases(cases, a.mutate)
    text = (json.dumps(cases, indent=1) + "\n").encode("utf-8")
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "cases.json"), "wb") as f:
        f.write(text)
    amb = ambient_doc()
    if a.mutate in AMBIENT_FILE_MUTATIONS:
        mutate_ambient(amb, a.mutate)
    amb_text = (json.dumps(amb, indent=1) + "\n").encode("utf-8")
    with open(os.path.join(a.out, "ambient.json"), "wb") as f:
        f.write(amb_text)
    sets = build(cases, hashlib.sha256(text).hexdigest(), a.mutate, hashlib.sha256(amb_text).hexdigest())
    if a.mutate:
        mutate_sets(sets, a.mutate)
    for rel, doc in sets.items():
        write(os.path.join(a.out, "runs", rel), doc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
