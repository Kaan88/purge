#!/usr/bin/env bash
# M1b executor score (docs/M1B_DESIGN.json M1B-RIG-EXEC, gates G5 and G6, criteria K10-K13; usage in vm/rig-m1b-exec.ps1):
# reads the pulled m1b-x-* runs and writes $M1B_OUT/m1b-exec-score.json (schema purge.rig.m1b-exec-score/1). Run
# from vm/ after the modes ran (vm/rig-m1b-exec.ps1):
#
#   bash truth/m1b-exec.sh
#
# Inputs, under $M1B_RUNS (default runs), run names <prefix><mode>:
#   m1b-x-fidelity    run.json (results.variants, execs, undo), execdiff-main.json, fidelity-main.json   K10, K11
#   m1b-x-traps       run.json (results.act_traps, execs), execdiff-traps.json                          K10, K12
#   m1b-x-undo-traps  run.json (results.undo_traps, undo)                                               K12
#   m1b-x-crash       run.json, crash-matrix.json                                                       K13
#   m1b-x-elevated    elevated-tests.json (the M1b elevated purge-win / purge-exec tests)               E1
# and truth/m1b-exec-cases.json (the variants, traps, fault points and power-off rounds the runs must cover).
# Every criterion is judged again here from the run records and the rigtool verdicts; the guest's own `pass`
# fields are not trusted.
#
# Exit codes: 0 every criterion passes; 1 a criterion fails; 2 an input is missing (the score is still written,
# FAIL, with the missing inputs listed under `missing`).
#
# Environment:
#   M1B_RUNS    directory holding the run dirs (default runs)
#   M1B_PREFIX  run-name prefix (default empty)
#   M1B_OUT     directory for m1b-exec-score.json (default truth)
#   M1B_CASES   the cases file (default truth/m1b-exec-cases.json)
#   PYTHON      Python 3 interpreter (default python)
set -euo pipefail
cd "$(dirname "$0")/.."

M1B_RUNS="${M1B_RUNS:-runs}"
M1B_PREFIX="${M1B_PREFIX:-}"
M1B_OUT="${M1B_OUT:-truth}"
M1B_CASES="${M1B_CASES:-truth/m1b-exec-cases.json}"
mkdir -p "$M1B_OUT"

PY="${PYTHON:-python}"

"$PY" -I - "$M1B_RUNS" "$M1B_PREFIX" "$M1B_OUT" "$M1B_CASES" <<'EOF'
import datetime, json, os, sys

runs_dir, prefix, out_dir, cases_path = sys.argv[1:5]
KINDS = ["service", "task", "firewall"]
missing = []


def load(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def need(path, what):
    d = load(path)
    if d is None:
        missing.append(what)
    return d


def rpath(mode, name):
    return os.path.join(runs_dir, prefix + mode, name)


def results(run):
    return (run or {}).get("results") or {}


def phases_ok(run):
    return bool(run) and bool(run.get("finished")) and all((p or {}).get("ok") for p in (run.get("phases") or []))


def kind_of(x):
    return (x or {}).get("kind")


cases = need(cases_path, "cases " + cases_path) or {}

fid_run = need(rpath("m1b-x-fidelity", "run.json"), prefix + "m1b-x-fidelity/run.json")
fid_ed = need(rpath("m1b-x-fidelity", "execdiff-main.json"), prefix + "m1b-x-fidelity/execdiff-main.json")
fid_fd = need(rpath("m1b-x-fidelity", "fidelity-main.json"), prefix + "m1b-x-fidelity/fidelity-main.json")
trp_run = need(rpath("m1b-x-traps", "run.json"), prefix + "m1b-x-traps/run.json")
trp_ed = need(rpath("m1b-x-traps", "execdiff-traps.json"), prefix + "m1b-x-traps/execdiff-traps.json")
ut_run = need(rpath("m1b-x-undo-traps", "run.json"), prefix + "m1b-x-undo-traps/run.json")
cr_run = need(rpath("m1b-x-crash", "run.json"), prefix + "m1b-x-crash/run.json")
cr_mx = need(rpath("m1b-x-crash", "crash-matrix.json"), prefix + "m1b-x-crash/crash-matrix.json")
el = need(rpath("m1b-x-elevated", "elevated-tests.json"), prefix + "m1b-x-elevated/elevated-tests.json")

# ---------------------------------------------------------------------------------------------- K10 collateral
def ed_row(name, ed):
    c = (ed or {}).get("counts") or {}
    return {"file": name, "present": ed is not None, "ok": bool((ed or {}).get("ok")), "collateral": c.get("collateral"),
            "guard_escapes": c.get("guard_escapes"), "unexplained": c.get("unexplained"), "missing_effects": c.get("missing_effects"),
            "changed_not_done": c.get("changed_not_done")}


k10_rows = [ed_row("m1b-x-fidelity/execdiff-main.json", fid_ed), ed_row("m1b-x-traps/execdiff-traps.json", trp_ed)]
k10_crash = []
for r in (cr_mx or {}).get("rows") or []:
    if r and r.get("execdiff_ok") is not None:
        k10_crash.append({"tag": r.get("tag"), "execdiff_ok": r.get("execdiff_ok")})
k10 = {
    "execdiffs": k10_rows, "crash_execdiffs": len(k10_crash), "crash_execdiffs_failing": [x["tag"] for x in k10_crash if x["execdiff_ok"] is not True],
    "collateral": sum((x["collateral"] or 0) for x in k10_rows),
}
k10["pass"] = bool(all(x["present"] and x["ok"] and x["collateral"] == 0 and x["guard_escapes"] == 0 for x in k10_rows)
                   and not k10["crash_execdiffs_failing"])

# ---------------------------------------------------------------------------------------------- K11 undo fidelity
want_variants = {v["id"]: v for v in (cases.get("fidelity") or {}).get("variants") or []}
got_variants = {v.get("id"): v for v in (results(fid_run).get("variants") or []) if v}
fid_ops = {}
for o in (fid_fd or {}).get("ops") or []:
    fid_ops[str(o.get("id"))] = o


def sha(x):
    return (x or {}).get("sha256")


k11_rows = []
for vid, w in want_variants.items():
    g = got_variants.get(vid) or {}
    planted = g.get("planted") or {}
    ex = g.get("exec") or {}
    un = g.get("undo") or {}
    op = fid_ops.get(str(ex.get("op"))) if ex.get("op") is not None else None
    row = {"id": vid, "kind": w.get("kind"), "expect": w.get("expect"), "recorded": g.get("recorded"),
           "band": (g.get("offered") or {}).get("band"), "selected": g.get("selected"), "exec": ex.get("kind"),
           "reason": ex.get("reason"), "undo": un.get("result"), "undo_kind": un.get("kind"),
           "fidelity_objects": (op or {}).get("objects"), "fidelity_differing": (op or {}).get("differing"),
           "gone_after_exec": (g.get("after_exec") or {}).get("present") is False,
           "state_equal_after_undo": bool(planted.get("present")) and sha(g.get("after_undo")) == sha(planted),
           "unchanged_after_exec": bool(planted.get("present")) and sha(g.get("after_exec")) == sha(planted),
           "problems": []}
    if not g:
        row["problems"].append("variant not in the run")
    elif w.get("expect") == "full":
        if row["band"] != "Safe":
            row["problems"].append("not offered Safe (%s)" % row["band"])
        if row["exec"] != "Done":
            row["problems"].append("exec %s" % row["exec"])
        if not row["gone_after_exec"]:
            row["problems"].append("still present after exec")
        if not (row["undo"] == "Finished" and row["undo_kind"] == "Restored"):
            row["problems"].append("undo %s/%s" % (row["undo"], row["undo_kind"]))
        if not (op and (op.get("objects") or 0) > 0 and op.get("differing") == 0):
            row["problems"].append("fidelity op objects %s differing %s" % (row["fidelity_objects"], row["fidelity_differing"]))
        if not row["state_equal_after_undo"]:
            row["problems"].append("object state after undo differs from the planted one")
    else:
        # A refused shape: never deleted, byte-equal after exec and after undo.
        if row["exec"] in ("Done", "Vanished", "PendingDelete"):
            row["problems"].append("refused shape executed (%s)" % row["exec"])
        if not row["unchanged_after_exec"]:
            row["problems"].append("changed by exec")
        if not row["state_equal_after_undo"]:
            row["problems"].append("changed after undo")
    row["pass"] = not row["problems"]
    k11_rows.append(row)
mins = (cases.get("fidelity") or {}).get("min_full") or {}
full_pass = {k: sum(1 for r in k11_rows if r["kind"] == k and r["expect"] == "full" and r["pass"]) for k in KINDS}
fid_run_exec = (results(fid_run).get("execs") or {}).get("main") or {}
k11 = {"variants": k11_rows, "full_passing": full_pass, "min_full": mins, "fidelity_ok": bool((fid_fd or {}).get("ok")),
       "fidelity_rows": [{"action": r.get("action"), "ops": r.get("ops"), "objects": r.get("objects"), "differing": r.get("differing"),
                          "percent": r.get("percent"), "pass": r.get("pass")} for r in (fid_fd or {}).get("rows") or []
                         if r and r.get("action") in ("DeleteService", "DeleteTask", "DeleteFirewallRule")],
       "normalisations": len((fid_fd or {}).get("normalisations") or []), "exec_exit": fid_run_exec.get("exit"),
       "undo_exit": ((results(fid_run).get("undo") or {}).get("main") or {}).get("exit"), "run_phases_ok": phases_ok(fid_run)}
k11["pass"] = bool(want_variants and k11["fidelity_ok"] and all(r["pass"] for r in k11_rows)
                   and all(full_pass.get(k, 0) >= int(mins.get(k, 0)) for k in KINDS) and k11["undo_exit"] == 0 and k11["run_phases_ok"])

# ---------------------------------------------------------------------------------------------- K12 traps
want_act = {c["id"]: c for c in (cases.get("act_traps") or {}).get("cases") or []}
got_act = {t.get("id"): t for t in (results(trp_run).get("act_traps") or []) if t}
act_rows = []
for tid, w in want_act.items():
    g = got_act.get(tid) or {}
    ex = g.get("exec") or {}
    row = {"id": tid, "change": w.get("change"), "changed": g.get("changed"), "exec": ex.get("kind"), "reason": ex.get("reason"),
           "blocker": ex.get("blocker"), "problems": []}
    if not g:
        row["problems"].append("trap not in the run")
    elif g.get("changed") is not True:
        row["problems"].append("the change was not made: %s" % g.get("change_error"))
    elif w.get("expect") == "twin-untouched":
        tb, ta = g.get("twin_before") or {}, g.get("twin_after") or {}
        row["twin_equal"] = bool(tb.get("present") and ta.get("present") and sha(ta) == sha(tb))
        if not row["twin_equal"]:
            row["problems"].append("the same-name twin changed or is gone")
        if row["exec"] == "Failed":
            row["problems"].append("the planned rule's op failed")
    else:
        row["deleted"] = (g.get("after_exec") or {}).get("present") is False
        row["unchanged"] = sha(g.get("after_exec")) == sha(g.get("after_change")) and (g.get("after_exec") or {}).get("present") is True
        if row["exec"] != "Skipped" or row["reason"] not in (w.get("reasons") or []):
            row["problems"].append("outcome %s/%s, want Skipped with %s" % (row["exec"], row["reason"], "|".join(w.get("reasons") or [])))
        elif w.get("blocker") and row["reason"] == "GateBlocked" and w["blocker"] not in str(row["blocker"]):
            row["problems"].append("blocker %s, want %s" % (row["blocker"], w["blocker"]))
        if row["deleted"]:
            row["problems"].append("DELETED after it changed")
        elif not row["unchanged"]:
            row["problems"].append("changed by exec")
    row["pass"] = not row["problems"]
    act_rows.append(row)
trp_exec = (results(trp_run).get("execs") or {}).get("traps") or {}
want_ut = {c["id"]: c for c in (cases.get("undo_traps") or {}).get("cases") or []}
got_ut = {t.get("id"): t for t in (results(ut_run).get("undo_traps") or []) if t}
ut_rows = []
for tid, w in want_ut.items():
    g = got_ut.get(tid) or {}
    un = g.get("undo") or {}
    row = {"id": tid, "trap": w.get("trap"), "set": g.get("set"), "undo": un.get("result"), "conflict": un.get("kind"),
           "expect": w.get("expect_conflict"), "problems": []}
    if not g:
        row["problems"].append("trap not in the run")
    elif g.get("set") is not True:
        row["problems"].append("the trap was not set: %s" % g.get("error"))
    else:
        if not (row["undo"] == "Conflict" and row["conflict"] == w.get("expect_conflict")):
            row["problems"].append("undo %s/%s, want Conflict/%s" % (row["undo"], row["conflict"], w.get("expect_conflict")))
        bu, au = g.get("before_undo") or {}, g.get("after_undo") or {}
        if w.get("trap") in ("impostor-service", "impostor-task"):
            row["overwritten"] = not (bu.get("present") and au.get("present") and sha(au) == sha(bu))
        elif w.get("trap") == "tamper-definition":
            row["overwritten"] = bool(au.get("present")) or g.get("definition_sha_after_undo") != g.get("definition_sha_after_trap")
        else:
            row["overwritten"] = bool(au.get("present")) or g.get("definition_present_after_undo") is not False
        if row["overwritten"]:
            row["problems"].append("OVERWRITTEN or created")
    row["pass"] = not row["problems"]
    ut_rows.append(row)
ut_exit = ((results(ut_run).get("undo") or {}).get("main") or {}).get("exit")
act_exit_want = (cases.get("act_traps") or {}).get("exec_exit") or []
ut_exit_want = (cases.get("undo_traps") or {}).get("undo_exit") or []
k12 = {"act": act_rows, "act_skipped": sum(1 for r in act_rows if r["pass"]), "act_total": len(want_act),
       "act_deleted": sum(1 for r in act_rows if r.get("deleted")), "exec_exit": trp_exec.get("exit"), "exec_exit_want": act_exit_want,
       "undo": ut_rows, "undo_conflicts": sum(1 for r in ut_rows if r["pass"]), "undo_total": len(want_ut),
       "undo_overwritten": sum(1 for r in ut_rows if r.get("overwritten")), "undo_exit": ut_exit, "undo_exit_want": ut_exit_want,
       "runs_phases_ok": phases_ok(trp_run) and phases_ok(ut_run)}
k12["pass"] = bool(want_act and want_ut and k12["act_skipped"] == k12["act_total"] and k12["act_deleted"] == 0
                   and k12["exec_exit"] in act_exit_want and k12["undo_conflicts"] == k12["undo_total"] and k12["undo_overwritten"] == 0
                   and k12["undo_exit"] in ut_exit_want and k12["runs_phases_ok"])

# ---------------------------------------------------------------------------------------------- K13 crash matrix
crash = cases.get("crash") or {}
planned = []
for k in KINDS:
    for fp in crash.get("fault_points") or []:
        if not fp.get("phase") or k not in (fp.get("kinds") or []):
            continue
        afters = crash.get("undo_afters") if fp["phase"] == "undo" else crash.get("exec_afters")
        for a in afters or []:
            planned.append((k, fp["point"], fp["phase"], a))
rows = [r for r in (cr_mx or {}).get("rows") or [] if r]


def row_pass(r):
    # The guest's rule (m1b-crash.ps1 Set-XRowPass), applied again.
    if not r.get("hit"):
        return False
    ok = (r.get("error") is None and r.get("crashed") and r.get("recover_exit") == 0 and r.get("recover2_exit") == 0
          and r.get("recover_idempotent") is True and r.get("after_exit") == 0 and r.get("fidelity_ok") is True and r.get("object_restored") is True)
    if r.get("phase") == "exec" and r.get("after") == "resume":
        ok = ok and r.get("execdiff_ok") is True and r.get("undo_exit") == 0
    if r.get("phase") == "undo":
        ok = ok and r.get("undone_by_recovery") is True
    if r.get("kind") == "poweroff":
        ok = ok and r.get("boot_changed") is True and r.get("pfro_unchanged") is True
    return bool(ok)


abort = [r for r in rows if r.get("kind") != "poweroff"]
unreached, failing = [], []
for (k, p, ph, a) in planned:
    rs = [r for r in abort if (r.get("object_kind"), r.get("point"), r.get("phase"), r.get("after")) == (k, p, ph, a)]
    key = "%s/%s/%s/%s" % (k, p, ph, a)
    if not any(r.get("hit") for r in rs):
        unreached.append(key)
    elif not any(row_pass(r) for r in rs):
        failing.append(key)
po = [r for r in rows if r.get("kind") == "poweroff"]
po_want = int((crash.get("poweroff") or {}).get("rounds_per_kind") or 0)
po_kinds = {k: {"rounds": sum(1 for r in po if r.get("object_kind") == k), "consistent": sum(1 for r in po if r.get("object_kind") == k and row_pass(r))} for k in KINDS}
declared = list(((results(cr_run).get("fault_points") or {}).get("declared")) or (cr_mx or {}).get("points") or [])
listed = [fp.get("point") for fp in crash.get("fault_points") or []]
k13 = {"planned": len(planned), "rows": len(abort), "unreached": unreached, "failing": failing,
       "poweroff": po_kinds, "poweroff_want_per_kind": po_want,
       "poweroff_consistent": sum(v["consistent"] for v in po_kinds.values()), "poweroff_total_want": po_want * len(KINDS),
       "declared_points": declared, "declared_not_in_cases": [p for p in declared if p not in listed],
       "cases_not_declared": [p for p in listed if declared and p not in declared],
       "subset_run": bool((cr_mx or {}).get("kinds") or (cr_mx or {}).get("filter_points")), "run_phases_ok": phases_ok(cr_run)}
k13["pass"] = bool(planned and not unreached and not failing and declared and not k13["declared_not_in_cases"] and not k13["cases_not_declared"]
                   and all(v["rounds"] == po_want and v["consistent"] == po_want for v in po_kinds.values()) and po_want > 0
                   and not k13["subset_run"] and k13["run_phases_ok"])

# ---------------------------------------------------------------------------------------------- E1 elevated tests
want_el = (cases.get("elevated") or {}).get("targets") or []
got_el = {(t.get("crate"), t.get("test")): t for t in (el or {}).get("targets") or [] if t}
el_rows = []
for w in want_el:
    g = got_el.get((w["crate"], w["test"])) or {}
    tests = g.get("tests") or []
    passed = [t["name"] for t in tests if t.get("result") == "ok"]
    bad = [t["name"] + ":" + str(t.get("result")) for t in tests if t.get("result") != "ok"]
    probs = []
    if not g:
        probs.append("target not run")
    if g and g.get("exit") != 0:
        probs.append("exit %s" % g.get("exit"))
    if bad:
        probs.append("not ok: " + ", ".join(bad[:10]))
    if w.get("run") == "all":
        if len(passed) < int(w.get("min") or 0):
            probs.append("%d passed, want at least %s" % (len(passed), w.get("min")))
        pre = w.get("require_prefix") or ""
        if pre and sum(1 for n in passed if n.startswith(pre)) < int(w.get("prefix_min") or 0):
            probs.append("fewer than %s passing %s tests" % (w.get("prefix_min"), pre))
    for n in w.get("require_names") or []:
        if not any(p == n or p.endswith("::" + n) for p in passed):
            probs.append("%s did not pass" % n)
    el_rows.append({"crate": w["crate"], "test": w["test"], "passed": len(passed), "problems": probs, "pass": not probs})
e1 = {"targets": el_rows, "admin": bool((el or {}).get("admin"))}
e1["pass"] = bool(el_rows and e1["admin"] and all(r["pass"] for r in el_rows))

# ---------------------------------------------------------------------------------------------- report
crit = {"K10": k10, "K11": k11, "K12": k12, "K13": k13, "E1": e1}
failing_crit = [k for k, v in crit.items() if not v.get("pass")]
report = {
    "schema": "purge.rig.m1b-exec-score/1", "written": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "runs_dir": runs_dir, "prefix": prefix, "cases": cases_path, "missing": missing,
    "gates": {"G5": {"criteria": ["K10", "K11", "K12"], "pass": not missing and all(crit[k]["pass"] for k in ("K10", "K11", "K12"))},
              "G6": {"criteria": ["K13", "E1"], "pass": not missing and all(crit[k]["pass"] for k in ("K13", "E1"))}},
    "criteria": crit, "failing": failing_crit,
}
report["pass"] = not missing and not failing_crit
report["verdict"] = "PASS" if report["pass"] else "FAIL"
out = os.path.join(out_dir, "m1b-exec-score.json")
with open(out, "w", encoding="utf-8", newline="\n") as f:
    json.dump(report, f, indent=2)
    f.write("\n")
print("m1b exec score: %s (failing: %s; missing: %s) -> %s" % (report["verdict"], ", ".join(failing_crit) or "none", ", ".join(missing) or "none", out))
sys.exit(2 if missing else (0 if report["pass"] else 1))
EOF
