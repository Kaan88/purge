#!/usr/bin/env bash
# M2 gate report (docs/M2_DESIGN.json gate_procedure G0-G6; vm/RIG.md §11): reads the pulled M2 runs and writes
# $M2_OUT/m2-gate.json (schema purge.rig.m2gate/1) and $M2_OUT/m2-gate.md. Run from vm/ after the five modes ran:
#
#   bash truth/m2.sh
#
# Inputs, under $M2_RUNS (default runs), run names <prefix><mode> (rig.ps1 Get-M2RunName):
#   <p>m2-install   run.json (results.install, d_volume, checks)
#   <p>m2-traps     run.json, execdiff-*.json, fidelity-main.json, m2-traps-check-*.json (G1, G5)
#   <p>m2-fidelity  run.json, execdiff-*.json, fidelity-*.json, m2-fixtures-check-*.json (G2, G6)
#   <p>m2-crash     run.json, crash-matrix.json, crash-torn.json (G3)
#   <p>m2-reboot    run.json (G4)
#   <p>m2-elevated  elevated-tests.json (G7; rig.ps1 Invoke-M2ElevatedTests)
# Each gate is pass / fail from the rigtool verdicts and the run records; nothing is re-measured here.
#
# Exit codes: 0 every gate passes; 1 a gate fails; 2 an input run is missing (the report is still written, the
# missing runs listed under `missing`).
#
# Environment:
#   M2_RUNS    directory holding the run dirs (default runs)
#   M2_PREFIX  run-name prefix (default empty: m2-traps, ...)
#   M2_OUT     directory for m2-gate.json / m2-gate.md (default results)
#   PYTHON     Python 3 interpreter (default python)
set -euo pipefail
cd "$(dirname "$0")/.."

M2_RUNS="${M2_RUNS:-runs}"
M2_PREFIX="${M2_PREFIX:-}"
M2_OUT="${M2_OUT:-results}"
mkdir -p "$M2_OUT"

PY="${PYTHON:-python}"   # as truth/m1a.sh; PYTHON=python3 where 'python' is not Python 3

"$PY" -I - "$M2_RUNS" "$M2_PREFIX" "$M2_OUT" <<'EOF'
import datetime, glob, json, os, sys

runs_dir, prefix, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
MODES = ["m2-install", "m2-traps", "m2-fidelity", "m2-crash", "m2-reboot"]
# Rows the fixture run must exercise (G2); typed service / task / firewall execution is deferred in v1, so those
# rows are reported but not required, and must stay untouched (ops 0).
REQUIRED_ROWS = ["QuarantineMove file", "QuarantineMove dir", "RemoveDirIfEmpty", "DeleteKeyTree",
                 "DeleteKeyIfEmpty", "DeleteValue", "EditSegment"]
DEFERRED_ROWS = ["DeleteService", "DeleteTask", "DeleteFirewallRule"]


def load(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def rdir(mode):
    return os.path.join(runs_dir, prefix + mode)


def res(run, *keys, default=None):
    cur = (run or {}).get("results") or {}
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def files(mode, pattern):
    return sorted(glob.glob(os.path.join(rdir(mode), pattern)))


def base(p):
    return os.path.basename(p)


missing = []
inputs = {}
runs = {}
for m in MODES:
    rj = load(os.path.join(rdir(m), "run.json"))
    runs[m] = rj
    if rj is None:
        missing.append(prefix + m)
        inputs[m] = {"run": prefix + m, "present": False}
        continue
    failed = [p.get("name") for p in rj.get("phases") or [] if p and not p.get("ok")]
    inputs[m] = {"run": prefix + m, "present": True, "finished": bool(rj.get("finished")),
                 "stages": [s.get("stage") for s in rj.get("stages") or [] if s],
                 "failed_phases": failed, "engine_calls": len((rj.get("engine") or {}).get("calls") or [])}


def run_ok(m):
    i = inputs[m]
    return i.get("present") and i.get("finished") and not i.get("failed_phases")


def execdiffs(mode):
    out = {}
    for p in files(mode, "execdiff-*.json"):
        d = load(p) or {}
        c = d.get("counts") or {}
        out[base(p)[len("execdiff-"):-len(".json")]] = {
            "ok": d.get("ok") is True,
            "guard_escapes": c.get("guard_escapes"), "collateral": c.get("collateral"),
            "unexplained": c.get("unexplained"), "missing_effects": c.get("missing_effects"),
            "trap_mismatches": c.get("trap_mismatches"), "changed_not_done": c.get("changed_not_done"),
            "traps_failing": [t.get("id") for t in d.get("traps") or [] if t and t.get("verdict") not in (None, "pass")],
            "ambient": (d.get("inputs") or {}).get("ambient"),
            "collateral_rows": ["%s %s%s" % (r.get("change"), r.get("path"), "|" + r["name"] if r.get("name") is not None else "")
                                for r in (d.get("collateral") or [])[:40] if r],
        }
    return out


def total(eds, key):
    return sum(int(v.get(key) or 0) for v in eds.values())


def fidelity(p):
    d = load(p)
    if d is None:
        return None
    rows = {}
    for r in d.get("rows") or []:
        if r:
            rows[r.get("action")] = {k: r.get(k) for k in ("ops", "objects", "identical", "differing", "percent", "pass")}
    differing_ops = [o.get("id") for o in d.get("ops") or [] if o and int(o.get("differing") or 0) > 0]
    return {"ok": d.get("ok") is True, "rows": rows, "differing_ops": differing_ops}


def checks(mode, pattern, strip):
    out = {}
    for p in files(mode, pattern):
        d = load(p) or {}
        out[base(p)[len(strip):-len(".json")]] = d.get("ok") is True
    return out


# ------------------------------------------------------------------------------------------- G0 install
run = runs["m2-install"]
g0 = {"present": run is not None}
if run is not None:
    inst = res(run, "install") or {}
    dv = res(run, "d_volume") or {}
    g0.update({
        "install_exit": inst.get("exit"), "rerun_exit": inst.get("rerun_exit"), "rerun_unchanged": inst.get("rerun_changed") is False,
        "check_exit": inst.get("check_exit"), "renamed_aside": inst.get("renamed_aside"),
        "traps_after_install_ok": res(run, "checks", "after-install") == 0,
        "trap_checks": checks("m2-install", "m2-traps-check-*.json", "m2-traps-check-"),
        "d_volume": dv,
    })
    # D: queue (needs engine ceb5999 or later, which accepts a NETWORK SERVICE-owned volume root): the exec moves
    # the payload into the engine's own D:\.purge-q\<session>\000001\, the user's pre-created D:\.purge-q is
    # renamed aside with user-marker.txt intact, never adopted.
    d_ok = (not dv.get("present")) or (dv.get("exec_exit") == 0 and dv.get("payload_gone") is True and dv.get("renamed_aside") is True
                                       and dv.get("user_marker_intact") is True and dv.get("adopted") is False
                                       and bool(dv.get("payload_in_queue")))
    g0["pass"] = bool(run_ok("m2-install") and inst.get("exit") == 0 and g0["rerun_unchanged"] and inst.get("check_exit") == 0
                      and g0["traps_after_install_ok"] and all(g0["trap_checks"].values()) and d_ok)
else:
    g0["pass"] = False

# ------------------------------------------------------------------------------------- G1 traps, G5 expiry
run = runs["m2-traps"]
g1 = {"present": run is not None}
g5 = {"present": run is not None}
if run is not None:
    eds = execdiffs("m2-traps")
    rf = res(run, "refusals") or {}
    refusals = {k: bool((rf.get(k) or {}).get("refused")) and (rf.get(k) or {}).get("new_sessions") == 0
                for k in ("wrong_confirm", "tampered_sidecar", "reordered_plan")}
    tc = checks("m2-traps", "m2-traps-check-*.json", "m2-traps-check-")
    fm = fidelity(os.path.join(rdir("m2-traps"), "fidelity-main.json"))
    ff = res(run, "forged_fp") or {}
    g1.update({
        "guard_escapes": total(eds, "guard_escapes"), "collateral": total(eds, "collateral"),
        "unexplained": total(eds, "unexplained"), "trap_mismatches": total(eds, "trap_mismatches"),
        "missing_effects": total(eds, "missing_effects"),
        "groups": eds, "groups_expected": ["main", "race-a", "race-b"],
        "refusals": refusals, "refusals_no_change": rf.get("no_change") is True,
        "tampered_sidecar_applied": (rf.get("tampered_sidecar") or {}).get("tampered") is True,
        "forged_fp_ok": ff.get("ok") is True, "forged_fp_violations": ff.get("violations") or [],
        "trap_checks": tc, "undo_fidelity_ok": (fm or {}).get("ok") is True,
    })
    g1["pass"] = bool(run_ok("m2-traps") and all(g in eds for g in g1["groups_expected"]) and all(v["ok"] for v in eds.values())
                      and g1["guard_escapes"] == 0 and g1["collateral"] == 0 and all(refusals.values())
                      and g1["refusals_no_change"] and g1["tampered_sidecar_applied"] and g1["forged_fp_ok"]
                      and tc and all(tc.values()) and g1["undo_fidelity_ok"])
    ex = res(run, "expiry") or {}
    g5.update({"listed": ex.get("listed") is True, "ids": ex.get("ids") or [], "plant_exit": ex.get("plant_exit"),
               "expiring_exit": ex.get("expiring_exit"), "purge_exit": ex.get("purge_exit"),
               "clock_env": ex.get("env") or [], "check_after_expiry_ok": tc.get("after-expiry") is True,
               "store_after_expiry": bool(res(run, "store_after_expiry"))})
    g5["pass"] = bool(g5["listed"] and ex.get("plant_exit") == 0 and ex.get("expiring_exit") == 0 and ex.get("purge_exit") == 0
                      and g5["check_after_expiry_ok"])
else:
    g1["pass"] = g5["pass"] = False

# ------------------------------------------------------------------------------- G2 fidelity, G6 restore point
run = runs["m2-fidelity"]
g2 = {"present": run is not None}
g6 = {"present": run is not None}
if run is not None:
    eds = execdiffs("m2-fidelity")
    fmain = fidelity(os.path.join(rdir("m2-fidelity"), "fidelity-main.json")) or {"ok": False, "rows": {}, "differing_ops": []}
    apps = {}
    for p in files("m2-fidelity", "fidelity-app-*.json"):
        apps[base(p)[len("fidelity-app-"):-len(".json")]] = fidelity(p)
    rows = fmain["rows"]
    missing_rows = [r for r in REQUIRED_ROWS if not (rows.get(r) or {}).get("ops")]
    failing_rows = [a for a, r in rows.items() if r.get("pass") is not True]
    touched_deferred = [r for r in DEFERRED_ROWS if (rows.get(r) or {}).get("ops")]
    fc = checks("m2-fidelity", "m2-fixtures-check-*.json", "m2-fixtures-check-")
    pu = res(run, "partial_undo") or {}
    uc = res(run, "undo_conflict") or {}
    bt = res(run, "backup_tamper") or {}
    ft = fidelity(os.path.join(rdir("m2-fidelity"), "fidelity-tamper.json")) or {"differing_ops": []}
    g2.update({
        "rows": rows, "required_rows_missing": missing_rows, "failing_rows": failing_rows, "deferred_rows_touched": touched_deferred,
        "collateral": total(eds, "collateral"), "guard_escapes": total(eds, "guard_escapes"), "execdiff": eds,
        "fixture_checks": fc, "apps": {k: (v or {}).get("ok") is True for k, v in apps.items()},
        "app_runs": res(run, "apps") or {},
        "partial_undo": {"undo_exit": pu.get("undo_exit"), "undone": len(pu.get("undone") or []), "not_undone": len(pu.get("not_undone") or [])},
        "undo_conflict": {"item": uc.get("item"), "recreated": uc.get("recreated"), "kept": uc.get("kept"), "reported": uc.get("reported"), "undo_exit": uc.get("undo_exit")},
        "backup_tamper": {"backup": bt.get("backup"), "undo_exit": bt.get("undo_exit"), "differing_ops": ft["differing_ops"]},
    })
    g2["undo_fidelity_100"] = bool(fmain["ok"] and not failing_rows)
    g2["pass"] = bool(run_ok("m2-fidelity") and g2["undo_fidelity_100"] and not missing_rows and not touched_deferred
                      and g2["collateral"] == 0 and g2["guard_escapes"] == 0 and all(v["ok"] for v in eds.values())
                      and fc and all(fc.values()) and apps and all(g2["apps"].values())
                      and pu.get("undo_exit") == 0 and uc.get("kept") is True and uc.get("reported") is True
                      and len(ft["differing_ops"]) == 1)
    rp = res(run, "restore_point") or {}
    first = rp.get("first") or {}
    second = rp.get("second") or {}
    created = isinstance(rp.get("before"), int) and isinstance(rp.get("after"), int) and rp["after"] > rp["before"]
    throttled = "throttled" in json.dumps(second.get("restore_point")).lower()
    off = res(run, "restore_point_off") or {}
    # Exec exit 0 or 10 (partial: an unrelated fixture item not done) with a report: G6 judges the restore point
    # outcome; the fixture items are G2's (RIG.md 11.5).
    ran = lambda x: x.get("exit") in (0, 10) and x.get("restore_point") is not None
    off_ok = bool(off.get("disabled") and ran(off) and "disabled" in json.dumps(off.get("restore_point")).lower()
                  and (off.get("done") or 0) > 0 and off.get("reenabled"))
    g6.update({"snapshot": rp.get("snapshot"), "before": rp.get("before"), "after": rp.get("after"), "after_second": rp.get("after_second"),
               "first": first, "second": second, "created": created, "second_throttled": throttled,
               "frequency_before": rp.get("frequency_before"), "frequency_value": rp.get("frequency_value"),
               "protection_off": off, "protection_off_ok": off_ok})
    g6["pass"] = bool(ran(first) and ran(second) and created and throttled and off_ok)
else:
    g2["pass"] = g6["pass"] = False

# ------------------------------------------------------------------------------------------- G3 crash
run = runs["m2-crash"]
g3 = {"present": run is not None}
if run is not None:
    mx = load(os.path.join(rdir("m2-crash"), "crash-matrix.json")) or {}
    rows = [r for r in mx.get("rows") or [] if r]
    abort = [r for r in rows if r.get("kind", "abort") == "abort"]
    power = [r for r in rows if r.get("kind") == "poweroff"]
    torn = load(os.path.join(rdir("m2-crash"), "crash-torn.json")) or {}
    failing = [r.get("tag") for r in rows if r.get("hit") and not r.get("pass")]
    errors = [r.get("tag") for r in rows if r.get("error")]
    g3.update({
        "points": mx.get("points") or [], "rows": len(rows), "hit": sum(1 for r in abort if r.get("hit")),
        "passed": sum(1 for r in rows if r.get("pass")),
        "not_hit": sorted({"%s/%s" % (r.get("point"), r.get("phase")) for r in abort if not r.get("hit")}),
        "failing": failing, "errors": errors,
        "recover_not_idempotent": [r.get("tag") for r in rows if r.get("hit") and r.get("recover_idempotent") is not True],
        "poweroff": {"rows": len(power), "passed": sum(1 for r in power if r.get("pass")), "points": [r.get("point") for r in power]},
        "torn": {"tail_pass": (torn.get("tail") or {}).get("pass") is True, "middle_pass": (torn.get("middle") or {}).get("pass") is True},
        "complete": res(run, "crash", "complete") is True,
    })
    g3["pass"] = bool(run_ok("m2-crash") and g3["complete"] and rows and not failing and not errors and g3["hit"] > 0
                      and g3["torn"]["tail_pass"] and g3["torn"]["middle_pass"])
else:
    g3["pass"] = False

# ------------------------------------------------------------------------------------------- G4 reboot
run = runs["m2-reboot"]
g4 = {"present": run is not None}
if run is not None:
    su = res(run, "scenario_u") or {}
    sr = res(run, "scenario_r") or {}
    rb = res(run, "reboot") or {}
    ru = res(run, "reboot_undo") or {}
    rt = res(run, "retry") or {}
    mm = res(run, "mismatch") or {}
    sm = res(run, "scenario_m") or {}
    g4.update({
        "undo_before_reboot": {"pfro_after_exec_ok": (su.get("pfro_after_exec") or {}).get("ok") is True, "pfro_restored": su.get("pfro_restored") is True,
                               "admin_outcome": su.get("admin_outcome"), "uw_outcome": su.get("uw_outcome")},
        "exec": {"pfro_after_exec_ok": (sr.get("pfro_after_exec") or {}).get("ok") is True, "admin_outcome": sr.get("admin_outcome"), "uw_outcome": sr.get("uw_outcome"),
                 "uw_forbidden_in_pfro": (sr.get("pfro_after_exec") or {}).get("forbidden") or []},
        "reconcile": {"boot_changed": rb.get("boot_changed") is True, "recover_exit": rb.get("recover_exit"), "recover2_exit": rb.get("recover2_exit"),
                      "pfro_restored": rb.get("pfro_restored") is True, "admin_moved": rb.get("admin_moved") is True,
                      "undo_exit": ru.get("undo_exit"), "fidelity_ok": ru.get("fidelity_ok") is True, "admin_restored": ru.get("admin_restored") is True},
        "retry": {"uw_outcome": rt.get("uw_outcome"), "skipped": rt.get("skipped") is True, "reason_ok": rt.get("reason_ok") is True, "check_exit": rt.get("check_exit")},
        "mismatch": {"pfro_after_exec_ok": (sm.get("pfro_after_exec") or {}).get("ok") is True, "boot_changed": mm.get("boot_changed") is True,
                     "recover_exit": mm.get("recover_exit"), "admin_present": mm.get("admin_present") is True, "admin_unchanged": mm.get("admin_unchanged") is True,
                     "fidelity_ok": mm.get("fidelity_ok") is True, "final_check_exit": res(run, "final_check_exit")},
    })
    u, e, r, t, x = g4["undo_before_reboot"], g4["exec"], g4["reconcile"], g4["retry"], g4["mismatch"]
    g4["reconcile_pass"] = bool(r["boot_changed"] and r["recover_exit"] == 0 and r["recover2_exit"] == 0 and r["pfro_restored"] and r["admin_moved"]
                                and r["undo_exit"] == 0 and r["fidelity_ok"] and r["admin_restored"])
    g4["mismatch_pass"] = bool(x["pfro_after_exec_ok"] and x["boot_changed"] and x["recover_exit"] == 0 and x["admin_present"] and x["admin_unchanged"] and x["fidelity_ok"])
    g4["pass"] = bool(run_ok("m2-reboot") and u["pfro_after_exec_ok"] and u["pfro_restored"] and e["pfro_after_exec_ok"] and not e["uw_forbidden_in_pfro"]
                      and g4["reconcile_pass"] and t["skipped"] and t["reason_ok"] and t["check_exit"] == 0
                      and g4["mismatch_pass"] and x["final_check_exit"] == 0)
else:
    g4["pass"] = False

# G7: the #[ignore]d elevated engine tests, run in the guest as admin (rig.ps1 Invoke-M2ElevatedTests, RIG.md 11.9).
ev = load(os.path.join(rdir("m2-elevated"), "elevated-tests.json"))
g7 = {"present": ev is not None}
if ev is None:
    missing.append(prefix + "m2-elevated")
    inputs["m2-elevated"] = {"run": prefix + "m2-elevated", "present": False}
    g7["pass"] = False
else:
    inputs["m2-elevated"] = {"run": prefix + "m2-elevated", "present": True}
    tests = [t for t in ev.get("tests") or [] if t]
    g7.update({"admin": ev.get("admin") is True, "error": ev.get("error"),
               "tests": [{"crate": t.get("crate"), "name": t.get("name"), "exit": t.get("exit"), "passed": t.get("passed") is True,
                          "error": t.get("error")} for t in tests]})
    g7["pass"] = bool(ev.get("pass") is True and g7["admin"] and tests and all(t.get("passed") is True for t in tests))

gates = {"g0_install": g0, "g1_traps": g1, "g2_fidelity": g2, "g3_crash": g3, "g4_reboot": g4, "g5_expiry": g5, "g6_restore_point": g6,
         "g7_elevated_tests": g7}
totals = {
    "guard_escapes": int(g1.get("guard_escapes") or 0) + int(g2.get("guard_escapes") or 0),
    "collateral": int(g1.get("collateral") or 0) + int(g2.get("collateral") or 0),
    "undo_fidelity_rows_failing": len(g2.get("failing_rows") or []),
    "required_rows_missing": len(g2.get("required_rows_missing") or []),
    "crash_failing": len(g3.get("failing") or []) + len(g3.get("errors") or []),
    "gates_failing": [k for k, v in gates.items() if not v.get("pass")],
}
report = {
    "schema": "purge.rig.m2gate/1",
    "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "runs_dir": runs_dir, "prefix": prefix, "inputs": inputs, "missing": missing,
}
report.update(gates)
report["totals"] = totals
report["pass"] = not missing and not totals["gates_failing"]

with open(os.path.join(out_dir, "m2-gate.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(report, f, indent=2, sort_keys=False)
    f.write("\n")


def yn(v):
    return "pass" if v else "FAIL"


md = ["# M2 gate", "", "Generated %s from `%s` (prefix `%s`). Schema purge.rig.m2gate/1, details in m2-gate.json." % (report["generated"], runs_dir, prefix), ""]
if missing:
    md += ["**Missing runs:** " + ", ".join(missing), ""]
md += ["| Gate | Result | Key figures |", "|---|---|---|"]
md.append("| G0 install hardening | %s | install exit %s, re-run unchanged %s, check exit %s, D: exec %s, renamed aside %s, marker intact %s, adopted %s, payload in queue %s |" % (
    yn(g0["pass"]), g0.get("install_exit"), g0.get("rerun_unchanged"), g0.get("check_exit"),
    *[(g0.get("d_volume") or {}).get(k) for k in ("exec_exit", "renamed_aside", "user_marker_intact", "adopted", "payload_in_queue")]))
md.append("| G1 traps | %s | guard_escapes %s, collateral %s, refusals %s, forged fp ok %s |" % (
    yn(g1["pass"]), g1.get("guard_escapes"), g1.get("collateral"), g1.get("refusals"), g1.get("forged_fp_ok")))
md.append("| G2 fidelity | %s | failing rows %s, required rows missing %s, collateral %s, apps %s |" % (
    yn(g2["pass"]), g2.get("failing_rows"), g2.get("required_rows_missing"), g2.get("collateral"), g2.get("apps")))
md.append("| G3 crash | %s | rows %s, hit %s, failing %s, not hit %s, torn %s, power-off %s |" % (
    yn(g3["pass"]), g3.get("rows"), g3.get("hit"), g3.get("failing"), g3.get("not_hit"), g3.get("torn"), g3.get("poweroff")))
md.append("| G4 reboot | %s | reconcile %s, mismatch %s, retry skipped %s |" % (
    yn(g4["pass"]), g4.get("reconcile_pass"), g4.get("mismatch_pass"), (g4.get("retry") or {}).get("skipped")))
md.append("| G5 expiry | %s | listed %s, ids %s, purge exit %s, check after expiry %s |" % (
    yn(g5["pass"]), g5.get("listed"), g5.get("ids"), g5.get("purge_exit"), g5.get("check_after_expiry_ok")))
md.append("| G6 restore point | %s | created %s, second throttled %s, protection off ok %s |" % (
    yn(g6["pass"]), g6.get("created"), g6.get("second_throttled"), g6.get("protection_off_ok")))
md.append("| G7 elevated tests | %s | admin %s, %s |" % (
    yn(g7["pass"]), g7.get("admin"), ", ".join("%s %s" % (t["name"], "pass" if t["passed"] else "FAIL (%s)" % t.get("error")) for t in g7.get("tests") or []) or g7.get("error")))
md += ["", "Totals: " + json.dumps(totals), "", "Overall: **%s**" % ("PASS" if report["pass"] else "FAIL"), ""]
if g2.get("rows"):
    md += ["## G2 rows (fixture run)", "", "| Action | ops | objects | identical | differing | % | pass |", "|---|---|---|---|---|---|---|"]
    for a, r in g2["rows"].items():
        md.append("| %s | %s | %s | %s | %s | %s | %s |" % (a, r.get("ops"), r.get("objects"), r.get("identical"), r.get("differing"), r.get("percent"), r.get("pass")))
    md.append("")
coll = [(m, g, v) for m, gd in (("m2-traps", g1.get("groups") or {}), ("m2-fidelity", g2.get("execdiff") or {}))
        for g, v in gd.items() if v.get("collateral")]
if coll:
    md += ["## Collateral (first 40 records per execdiff)", ""]
    for m, g, v in coll:
        md.append("- %s execdiff-%s (%s, ambient %s):" % (m, g, v.get("collateral"), v.get("ambient")))
        md += ["  - `%s`" % r for r in v.get("collateral_rows") or []]
    md.append("")
with open(os.path.join(out_dir, "m2-gate.md"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(md))

print("m2 gate: %s (failing: %s; missing: %s) -> %s" % ("PASS" if report["pass"] else "FAIL", ", ".join(totals["gates_failing"]) or "none",
                                                       ", ".join(missing) or "none", os.path.join(out_dir, "m2-gate.json")))
sys.exit(2 if missing else (0 if report["pass"] else 1))
EOF
