#!/usr/bin/env bash
# M1b executor score (docs/M1B_DESIGN.json M1B-RIG-EXEC, gates G5 and G6, criteria K10-K13; usage in vm/rig-m1b-exec.ps1):
# reads the pulled m1b-x-* runs and writes $M1B_OUT/m1b-exec-score.json (schema purge.rig.m1b-exec-score/2). Run
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
# and truth/m1b-exec-cases.json (the variants, traps and fault points the guest planted from).
# Every criterion is judged again here from the run records and the rigtool verdicts; the guest's own `pass`
# fields are not trusted.
#
# The gate's minimums are NOT read from the cases file (review R4 S4; as vm/truth/m2.sh): the full variants per kind
# (2 / 4 / 3), the six act-time traps and the four undo traps with their expected outcomes, the crash rounds (every
# kind x reachable point x resume|rollback, GATE_ROUNDS), the 5 power-off rounds per kind and the elevated test
# targets are constants below. The cases file only says what the guest plants; a cases file that lowers a minimum,
# drops a trap or moves a point to not_reachable makes the runs miss a gate row, and the score FAILS. Each run records
# the SHA-256 of the cases bytes it got and the engine build it ran (review R4 S6): all runs must name the same cases
# file (the one scored here) and the same engine (sha256, installed copy equal, one repo commit, clean sources).
#
# The ambient set decides K10 as much as the cases file does (review R8 S3): the scorer hashes the committed set
# ($M1B_AMBIENT, default truth/m1b-exec-ambient.json; Purge-CleanPro: truth/m1b-exec-ambient-cleanpro.json) itself
# and requires, in all four VM runs, results.ambient.declared.sha256 == results.ambient.guest_sha256 == that hash. It
# also checks the file: schema purge.rig.m2ambient/1, at least MIN_NULL_RUNS_PER_MODE null runs of each null mode
# (a constant here, not read from anywhere), every run id of the null-run shape <prefix><k>-<mode>, and no fixture
# name (PurgeExec*, C:\ProgramData\Purge) in any record or pattern.
#
# Exit codes: 0 every criterion passes; 1 a criterion fails; 2 an input is missing (the score is still written,
# FAIL, with the missing inputs listed under `missing`).
#
# Environment:
#   M1B_RUNS    directory holding the run dirs (default runs)
#   M1B_PREFIX  run-name prefix (default empty)
#   M1B_OUT     directory for m1b-exec-score.json (default truth)
#   M1B_CASES   the cases file (default truth/m1b-exec-cases.json)
#   M1B_AMBIENT the committed M1b exec ambient set (default truth/m1b-exec-ambient.json)
#   PYTHON      Python 3 interpreter (default python)
set -euo pipefail
cd "$(dirname "$0")/.."

M1B_RUNS="${M1B_RUNS:-runs}"
M1B_PREFIX="${M1B_PREFIX:-}"
M1B_OUT="${M1B_OUT:-truth}"
M1B_CASES="${M1B_CASES:-truth/m1b-exec-cases.json}"
M1B_AMBIENT="${M1B_AMBIENT:-truth/m1b-exec-ambient.json}"
mkdir -p "$M1B_OUT"

PY="${PYTHON:-python}"

"$PY" -I - "$M1B_RUNS" "$M1B_PREFIX" "$M1B_OUT" "$M1B_CASES" "$M1B_AMBIENT" <<'EOF'
import datetime, hashlib, json, os, re, sys

runs_dir, prefix, out_dir, cases_path, ambient_path = sys.argv[1:6]
KINDS = ["service", "task", "firewall"]
missing = []

# ------------------------------------------------------------------------------------------------ gate constants
# docs/M1B_DESIGN.json gate_criteria K11-K13 and gate_procedure G5/G6. Changing one of these changes the gate: it
# needs a design change and a review, never a cases-file edit.
MIN_FULL = {"service": 2, "task": 4, "firewall": 3}                      # K11
ACT_EXIT, UNDO_EXIT = [10], [11]                                          # K12: partial; undo with conflicts
SKIP_REASONS = ["GateBlocked", "ChangedSinceScan"]
GATE_ACT = {                                                              # K12: 5 skipped + 1 twin untouched
    "svc-running":   {"kind": "service", "expect": "skipped", "reasons": SKIP_REASONS, "blocker": "InUse", "scm_unchanged": True},
    "svc-repoint":   {"kind": "service", "expect": "skipped", "reasons": SKIP_REASONS},
    "svc-dependent": {"kind": "service", "expect": "skipped", "reasons": SKIP_REASONS, "blocker": "HasDependents"},
    "task-edit":     {"kind": "task", "expect": "skipped", "reasons": SKIP_REASONS},
    "fw-edit":       {"kind": "firewall", "expect": "skipped", "reasons": SKIP_REASONS},
    "fw-same-name":  {"kind": "firewall", "expect": "twin-untouched"},
}
ACT_SKIPPED_WANT, ACT_TWIN_WANT = 5, 1
GATE_UNDO = {                                                             # K12: 4 of 4 conflicts, 0 overwritten
    "svc-impostor":  {"variant": "svc-full", "trap": "impostor-service", "conflict": "ObjectExists"},
    "task-impostor": {"variant": "task-simple", "trap": "impostor-task", "conflict": "ObjectExists"},
    "def-tamper":    {"variant": "fw-program", "trap": "tamper-definition", "conflict": "BackupTampered"},
    "def-missing":   {"variant": "svc-localservice", "trap": "delete-definition", "conflict": "BackupMissing"},
}
# K13: the reachable fault points per phase and kind, and the afters each is run with. Every point purge-exec
# FAULT_POINTS declares must be here or in NOT_REACHABLE.
_EXEC_POINTS = ["journal.header", "backup.written", "backup.verified", "intent.flushed", "act.before", "act.after",
                "done.before", "group.end", "commit.before", "objdelete.after"]
GATE_POINTS = [(p, "exec", KINDS, ["resume", "rollback"]) for p in _EXEC_POINTS] + [
    # index.write is also hit by exec, after `commit` (crates/purge-exec/src/execute.rs step 11; review R4 S4): a
    # finished run has no rollback, so resume only.
    ("index.write", "exec", KINDS, ["resume"]),
    ("undo.intent", "undo", KINDS, ["resume"]),
    ("undo.act.after", "undo", KINDS, ["resume"]),
    ("index.write", "undo", KINDS, ["resume"]),
    ("svcrestore.mid", "undo", ["service"], ["resume"]),
    ("fwrestore.mid", "undo", ["firewall"], ["resume"]),
]
NOT_REACHABLE = {"regdelete.mid", "regrestore.mid", "expiry.mid", "bootmove.registered"}
GATE_ROUNDS = [(k, p, ph, a) for (p, ph, ks, afters) in GATE_POINTS for k in ks for a in afters]
POWEROFF_PER_KIND = 5                                                     # K13: 15 of 15
POWEROFF_FIRST = "objdelete.after"
# BIND, the ambient set (review R8 S3): the null runs it must be built from, per null mode, and what it must not name.
AMBIENT_SCHEMA = "purge.rig.m2ambient/1"
NULL_MODES = ["m1b-x-fidelity", "m1b-x-traps"]
MIN_NULL_RUNS_PER_MODE = 6                                                # vm/RIG.md 12.8: -Count 6
NULL_RUN_RX = re.compile(r"^[a-z0-9][a-z0-9_.-]*[0-9]-(m1b-x-fidelity|m1b-x-traps)$")
FIXTURE_RX = re.compile(r"(?i)purgeexec|programdata\\+purge")               # as rig-m1b-exec.ps1 $XFixtureRx
ELEVATED = [                                                              # E1
    {"crate": "purge-win", "test": "scm", "run": "all", "min": 12, "require_prefix": "elevated::", "prefix_min": 6},
    {"crate": "purge-win", "test": "firewall", "run": "all", "min": 12, "require_prefix": "rig::", "prefix_min": 10},
    {"crate": "purge-win", "test": "taskschd", "run": "all", "min": 11},
    {"crate": "purge-exec", "test": "act_service", "require_names": ["rig_live_delete_and_recreate_round_trip"]},
    {"crate": "purge-exec", "test": "act_task", "require_names": ["rig_live_delete_and_undo"]},
    {"crate": "purge-exec", "test": "act_firewall", "require_names": ["rig_live_delete_and_recreate_round_trip"]},
]


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


def is_int(x, v):
    return isinstance(x, int) and not isinstance(x, bool) and x == v


try:
    with open(cases_path, "rb") as f:
        cases_bytes = f.read()
    cases_sha = hashlib.sha256(cases_bytes).hexdigest()
    cases = json.loads(cases_bytes.decode("utf-8-sig"))
except (OSError, ValueError):
    cases_sha, cases = None, {}
    missing.append("cases " + cases_path)

try:
    with open(ambient_path, "rb") as f:
        amb_bytes = f.read()
    amb_sha = hashlib.sha256(amb_bytes).hexdigest()
    amb = json.loads(amb_bytes.decode("utf-8-sig"))
except (OSError, ValueError):
    amb_sha, amb = None, None
    missing.append("ambient " + ambient_path)

fid_run = need(rpath("m1b-x-fidelity", "run.json"), prefix + "m1b-x-fidelity/run.json")
fid_ed = need(rpath("m1b-x-fidelity", "execdiff-main.json"), prefix + "m1b-x-fidelity/execdiff-main.json")
fid_fd = need(rpath("m1b-x-fidelity", "fidelity-main.json"), prefix + "m1b-x-fidelity/fidelity-main.json")
trp_run = need(rpath("m1b-x-traps", "run.json"), prefix + "m1b-x-traps/run.json")
trp_ed = need(rpath("m1b-x-traps", "execdiff-traps.json"), prefix + "m1b-x-traps/execdiff-traps.json")
ut_run = need(rpath("m1b-x-undo-traps", "run.json"), prefix + "m1b-x-undo-traps/run.json")
cr_run = need(rpath("m1b-x-crash", "run.json"), prefix + "m1b-x-crash/run.json")
cr_mx = need(rpath("m1b-x-crash", "crash-matrix.json"), prefix + "m1b-x-crash/crash-matrix.json")
el = need(rpath("m1b-x-elevated", "elevated-tests.json"), prefix + "m1b-x-elevated/elevated-tests.json")

# ---------------------------------------------------------------------------------------------- binding (R4 S4, S6, R8 S3)
# One cases file, one ambient set (the committed one scored here) and one engine build for every run.
amb_problems = []
amb_info = {"file": ambient_path, "sha256": amb_sha, "schema": (amb or {}).get("schema") if isinstance(amb, dict) else None,
            "runs_per_mode": {}, "bad_run_ids": [], "fixture_names": [], "min_runs_per_mode": MIN_NULL_RUNS_PER_MODE}
if amb is not None:
    if not isinstance(amb, dict) or amb.get("schema") != AMBIENT_SCHEMA:
        amb_problems.append("ambient %s: schema %s, want %s" % (ambient_path, amb_info["schema"], AMBIENT_SCHEMA))
    a = amb if isinstance(amb, dict) else {}
    runs = [r for r in (a.get("runs") or []) if isinstance(r, dict)]
    ids = [str(r.get("id")) for r in runs]
    for m in NULL_MODES:
        amb_info["runs_per_mode"][m] = len({i for i in ids if NULL_RUN_RX.match(i) and i.endswith("-" + m)})
        if amb_info["runs_per_mode"][m] < MIN_NULL_RUNS_PER_MODE:
            amb_problems.append("ambient: %d null run(s) of %s, want at least %d" % (amb_info["runs_per_mode"][m], m, MIN_NULL_RUNS_PER_MODE))
    amb_info["bad_run_ids"] = [i for i in ids if not NULL_RUN_RX.match(i)] + sorted({i for i in ids if ids.count(i) > 1})
    if amb_info["bad_run_ids"]:
        amb_problems.append("ambient: run ids not of the null-run shape or repeated: %s" % ", ".join(amb_info["bad_run_ids"][:10]))
    if not isinstance(a.get("records"), list) or not isinstance(a.get("patterns"), list):
        amb_problems.append("ambient: records / patterns are not lists")
    entries = list(a.get("records") or []) + list(a.get("patterns") or [])
    for r in runs:
        entries += list(r.get("records") or []) + list(r.get("patterns") or [])
    amb_info["fixture_names"] = sorted({str(e) for e in entries if FIXTURE_RX.search(str(e))})
    if amb_info["fixture_names"]:
        amb_problems.append("ambient: %d entr(ies) name a fixture: %s" % (len(amb_info["fixture_names"]), " | ".join(amb_info["fixture_names"][:5])))
vm_runs = {"m1b-x-fidelity": fid_run, "m1b-x-traps": trp_run, "m1b-x-undo-traps": ut_run, "m1b-x-crash": cr_run}
bind_rows, bind_problems = [], list(amb_problems)
for mode, run in vm_runs.items():
    res = results(run)
    eb = res.get("engine_build") or {}
    decl = eb.get("declared") or {}
    ar = res.get("ambient") if isinstance(res.get("ambient"), dict) else {}
    row = {"run": prefix + mode, "cases_sha256": (res.get("cases") or {}).get("sha256"),
           "engine_sha256": decl.get("sha256"), "staged_sha256": eb.get("staged_sha256"),
           "installed_sha256": eb.get("installed_sha256"), "commit": decl.get("commit"), "source_dirty": decl.get("source_dirty"),
           "ambient_declared_sha256": (ar.get("declared") or {}).get("sha256") if isinstance(ar.get("declared"), dict) else None,
           "ambient_guest_sha256": ar.get("guest_sha256")}
    bind_rows.append(row)
    if run is None:
        continue
    if not row["cases_sha256"] or row["cases_sha256"] != cases_sha:
        bind_problems.append("%s: cases sha256 %s, scored file %s" % (row["run"], row["cases_sha256"], cases_sha))
    # The run's execdiffs used the committed ambient set: the host declared it and the guest copy is it (R8 S3).
    if not (amb_sha and row["ambient_declared_sha256"] == amb_sha and row["ambient_guest_sha256"] == amb_sha):
        bind_problems.append("%s: ambient declared %s, guest %s, committed %s" % (row["run"], row["ambient_declared_sha256"], row["ambient_guest_sha256"], amb_sha))
    if not row["engine_sha256"] or not (row["engine_sha256"] == row["staged_sha256"] == row["installed_sha256"]):
        bind_problems.append("%s: engine declared %s, staged %s, installed %s" % (row["run"], row["engine_sha256"], row["staged_sha256"], row["installed_sha256"]))
    if not row["commit"] or row["source_dirty"] is not False:
        bind_problems.append("%s: commit %s, source_dirty %s" % (row["run"], row["commit"], row["source_dirty"]))
el_bind = (el or {}).get("build") or {}
el_row = {"run": prefix + "m1b-x-elevated", "cases_sha256": (el or {}).get("cases_sha256"), "commit": el_bind.get("commit"),
          "source_dirty": el_bind.get("source_dirty")}
if el is not None:
    if el_row["cases_sha256"] != cases_sha:
        bind_problems.append("%s: cases sha256 %s, scored file %s" % (el_row["run"], el_row["cases_sha256"], cases_sha))
    if not el_row["commit"] or el_row["source_dirty"] is not False:
        bind_problems.append("%s: commit %s, source_dirty %s" % (el_row["run"], el_row["commit"], el_row["source_dirty"]))
present = [r for r, run in zip(bind_rows, vm_runs.values()) if run is not None]
engines = sorted({r["engine_sha256"] for r in present if r["engine_sha256"]})
commits = sorted({r["commit"] for r in present + ([el_row] if el is not None else []) if r["commit"]})
if len(engines) > 1:
    bind_problems.append("runs ran %d different engines: %s" % (len(engines), ", ".join(engines)))
if len(commits) > 1:
    bind_problems.append("runs name %d different commits: %s" % (len(commits), ", ".join(commits)))
binding = {"cases_sha256": cases_sha, "ambient": amb_info, "runs": bind_rows + [el_row], "engines": engines, "commits": commits,
           "problems": bind_problems}
binding["pass"] = bool(cases_sha and amb_sha and not bind_problems and len(engines) == 1 and len(commits) == 1)

# ---------------------------------------------------------------------------------------------- K10 collateral
def ed_row(name, ed):
    c = (ed or {}).get("counts") or {}
    return {"file": name, "present": ed is not None, "ok": bool((ed or {}).get("ok")), "collateral": c.get("collateral"),
            "guard_escapes": c.get("guard_escapes"), "unexplained": c.get("unexplained"), "missing_effects": c.get("missing_effects"),
            "changed_not_done": c.get("changed_not_done"), "ambient": ((ed or {}).get("inputs") or {}).get("ambient")}


k10_rows = [ed_row("m1b-x-fidelity/execdiff-main.json", fid_ed), ed_row("m1b-x-traps/execdiff-traps.json", trp_ed)]
k10_crash = []
for r in (cr_mx or {}).get("rows") or []:
    if r and r.get("execdiff_ok") is not None:
        k10_crash.append({"tag": r.get("tag"), "execdiff_ok": r.get("execdiff_ok"), "unexplained": r.get("execdiff_unexplained")})
k10 = {
    "execdiffs": k10_rows, "crash_execdiffs": len(k10_crash),
    "crash_execdiffs_failing": [x["tag"] for x in k10_crash if x["execdiff_ok"] is not True or not is_int(x["unexplained"], 0)],
    "collateral": sum((x["collateral"] or 0) for x in k10_rows),
    "unexplained": sum((x["unexplained"] or 0) for x in k10_rows),
}
# An added object nothing authorises (unexplained, after the ambient set) fails as collateral does (review R4 S2).
k10["pass"] = bool(all(x["present"] and x["ok"] and is_int(x["collateral"], 0) and is_int(x["guard_escapes"], 0)
                       and is_int(x["unexplained"], 0) for x in k10_rows)
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
full_pass = {k: sum(1 for r in k11_rows if r["kind"] == k and r["expect"] == "full" and r["pass"]) for k in KINDS}
fid_run_exec = (results(fid_run).get("execs") or {}).get("main") or {}
k11 = {"variants": k11_rows, "full_passing": full_pass, "min_full": MIN_FULL,
       "min_full_in_cases": (cases.get("fidelity") or {}).get("min_full"), "fidelity_ok": bool((fid_fd or {}).get("ok")),
       "fidelity_rows": [{"action": r.get("action"), "ops": r.get("ops"), "objects": r.get("objects"), "differing": r.get("differing"),
                          "percent": r.get("percent"), "pass": r.get("pass")} for r in (fid_fd or {}).get("rows") or []
                         if r and r.get("action") in ("DeleteService", "DeleteTask", "DeleteFirewallRule")],
       "normalisations": len((fid_fd or {}).get("normalisations") or []), "exec_exit": fid_run_exec.get("exit"),
       "undo_exit": ((results(fid_run).get("undo") or {}).get("main") or {}).get("exit"), "run_phases_ok": phases_ok(fid_run)}
k11["pass"] = bool(want_variants and k11["fidelity_ok"] and all(r["pass"] for r in k11_rows)
                   and all(full_pass.get(k, 0) >= MIN_FULL[k] for k in KINDS) and k11["undo_exit"] == 0 and k11["run_phases_ok"])

# ---------------------------------------------------------------------------------------------- K12 traps
got_act = {t.get("id"): t for t in (results(trp_run).get("act_traps") or []) if t}
act_rows = []
for tid, w in GATE_ACT.items():
    g = got_act.get(tid) or {}
    ex = g.get("exec") or {}
    row = {"id": tid, "expect": w["expect"], "change": g.get("change"), "changed": g.get("changed"), "exec": ex.get("kind"),
           "reason": ex.get("reason"), "blocker": ex.get("blocker"), "problems": []}
    if not g:
        row["problems"].append("trap not in the run")
    elif g.get("kind") != w["kind"]:
        row["problems"].append("trap kind %s, want %s" % (g.get("kind"), w["kind"]))
    elif g.get("changed") is not True:
        row["problems"].append("the change was not made: %s" % g.get("change_error"))
    elif w["expect"] == "twin-untouched":
        # The planned rule is deleted by its own id; the twin with the same display name is untouched (review R4 S5).
        tb, ta = g.get("twin_before") or {}, g.get("twin_after") or {}
        row["twin_equal"] = bool(tb.get("present") and ta.get("present") and sha(ta) == sha(tb))
        row["base_gone"] = (g.get("after_exec") or {}).get("present") is False
        if row["exec"] != "Done":
            row["problems"].append("the planned rule's op is %s, want Done" % row["exec"])
        if not row["base_gone"]:
            row["problems"].append("the planned rule is still present")
        if not row["twin_equal"]:
            row["problems"].append("the same-name twin changed or is gone")
    else:
        row["deleted"] = (g.get("after_exec") or {}).get("present") is False
        row["unchanged"] = sha(g.get("after_exec")) == sha(g.get("after_change")) and (g.get("after_exec") or {}).get("present") is True
        if row["exec"] != "Skipped" or row["reason"] not in w["reasons"]:
            row["problems"].append("outcome %s/%s, want Skipped with %s" % (row["exec"], row["reason"], "|".join(w["reasons"])))
        elif w.get("blocker") and row["reason"] == "GateBlocked" and w["blocker"] not in str(row["blocker"]):
            row["problems"].append("blocker %s, want %s" % (row["blocker"], w["blocker"]))
        if row["deleted"]:
            row["problems"].append("DELETED after it changed")
        elif not row["unchanged"]:
            row["problems"].append("changed by exec")
        if w.get("scm_unchanged"):
            # The service must still run, as the same process, after exec (review R4 S3).
            sb, sa = g.get("scm_after_change") or {}, g.get("scm_after_exec") or {}
            row["scm_before"], row["scm_after"] = sb, sa
            if not (sb.get("state") == "Running" and sa.get("state") == "Running" and isinstance(sb.get("pid"), int)
                    and sb.get("pid", 0) > 0 and sa.get("pid") == sb.get("pid")):
                row["problems"].append("service not running as the same process after exec (%s pid %s -> %s pid %s)"
                                       % (sb.get("state"), sb.get("pid"), sa.get("state"), sa.get("pid")))
    row["pass"] = not row["problems"]
    act_rows.append(row)
trp_exec = (results(trp_run).get("execs") or {}).get("traps") or {}
got_ut = {t.get("id"): t for t in (results(ut_run).get("undo_traps") or []) if t}
ut_rows = []
for tid, w in GATE_UNDO.items():
    g = got_ut.get(tid) or {}
    un = g.get("undo") or {}
    row = {"id": tid, "trap": w["trap"], "variant": g.get("variant"), "set": g.get("set"), "undo": un.get("result"),
           "conflict": un.get("kind"), "expect": w["conflict"], "problems": []}
    if not g:
        row["problems"].append("trap not in the run")
    elif g.get("trap") != w["trap"] or g.get("variant") != w["variant"]:
        row["problems"].append("trap %s on %s, want %s on %s" % (g.get("trap"), g.get("variant"), w["trap"], w["variant"]))
    elif g.get("set") is not True:
        row["problems"].append("the trap was not set: %s" % g.get("error"))
    else:
        if not (row["undo"] == "Conflict" and row["conflict"] == w["conflict"]):
            row["problems"].append("undo %s/%s, want Conflict/%s" % (row["undo"], row["conflict"], w["conflict"]))
        bu, au = g.get("before_undo") or {}, g.get("after_undo") or {}
        if w["trap"] in ("impostor-service", "impostor-task"):
            row["overwritten"] = not (bu.get("present") and au.get("present") and sha(au) == sha(bu))
        elif w["trap"] == "tamper-definition":
            row["overwritten"] = bool(au.get("present")) or not g.get("definition_sha_after_trap") \
                or g.get("definition_sha_after_undo") != g.get("definition_sha_after_trap")
        else:
            row["overwritten"] = bool(au.get("present")) or g.get("definition_present_after_undo") is not False
        if row["overwritten"]:
            row["problems"].append("OVERWRITTEN or created")
    row["pass"] = not row["problems"]
    ut_rows.append(row)
ut_exit = ((results(ut_run).get("undo") or {}).get("main") or {}).get("exit")
act_skipped = sum(1 for r in act_rows if r["pass"] and r["expect"] == "skipped")
act_twin = sum(1 for r in act_rows if r["pass"] and r["expect"] == "twin-untouched")
k12 = {"act": act_rows, "act_skipped": act_skipped, "act_skipped_want": ACT_SKIPPED_WANT,
       "act_twin_untouched": act_twin, "act_twin_want": ACT_TWIN_WANT,
       "act_summary": "%d of %d skipped + %d of %d twin untouched" % (act_skipped, ACT_SKIPPED_WANT, act_twin, ACT_TWIN_WANT),
       "act_deleted": sum(1 for r in act_rows if r.get("deleted")), "exec_exit": trp_exec.get("exit"), "exec_exit_want": ACT_EXIT,
       "undo": ut_rows, "undo_conflicts": sum(1 for r in ut_rows if r["pass"]), "undo_total": len(GATE_UNDO),
       "undo_overwritten": sum(1 for r in ut_rows if r.get("overwritten")), "undo_exit": ut_exit, "undo_exit_want": UNDO_EXIT,
       "runs_phases_ok": phases_ok(trp_run) and phases_ok(ut_run)}
k12["pass"] = bool(act_skipped == ACT_SKIPPED_WANT and act_twin == ACT_TWIN_WANT and all(r["pass"] for r in act_rows)
                   and k12["act_deleted"] == 0 and k12["exec_exit"] in ACT_EXIT and k12["undo_conflicts"] == len(GATE_UNDO)
                   and k12["undo_overwritten"] == 0 and k12["undo_exit"] in UNDO_EXIT and k12["runs_phases_ok"])

# ---------------------------------------------------------------------------------------------- K13 crash matrix
rows = [r for r in (cr_mx or {}).get("rows") or [] if r]


def row_pass(r):
    # The guest's rule (m1b-crash.ps1 Set-XRowPass), applied again.
    if not r.get("hit"):
        return False
    ok = (r.get("error") is None and r.get("crashed") and r.get("recover_exit") == 0 and r.get("recover2_exit") == 0
          and r.get("recover_idempotent") is True and r.get("after_exit") == 0 and r.get("fidelity_ok") is True and r.get("object_restored") is True)
    if r.get("phase") == "exec" and r.get("after") == "resume":
        ok = ok and r.get("execdiff_ok") is True and is_int(r.get("execdiff_unexplained"), 0) and r.get("undo_exit") == 0
    if r.get("phase") == "undo":
        ok = ok and r.get("undone_by_recovery") is True
    if r.get("kind") == "poweroff":
        # The cut must have landed inside the run: the journal read after the boot, before recovery, has no end of
        # the run (exec) or an undo intent without its end (undo) (review R4 S1).
        ok = ok and r.get("boot_changed") is True and r.get("pfro_unchanged") is True and r.get("cut_mid_run") is True
    return bool(ok)


abort = [r for r in rows if r.get("kind") != "poweroff"]
unreached, failing = [], []
for (k, p, ph, a) in GATE_ROUNDS:
    rs = [r for r in abort if (r.get("object_kind"), r.get("point"), r.get("phase"), r.get("after")) == (k, p, ph, a)]
    key = "%s/%s/%s/%s" % (k, p, ph, a)
    if not rs or not all(r.get("hit") for r in rs):
        unreached.append(key)
    elif not all(row_pass(r) for r in rs):
        failing.append(key)
po = [r for r in rows if r.get("kind") == "poweroff"]
po_kinds = {}
for k in KINDS:
    kr = [r for r in po if r.get("object_kind") == k]
    pts = [(r.get("point"), r.get("phase")) for r in kr]
    po_kinds[k] = {"rounds": len(kr), "consistent": sum(1 for r in kr if row_pass(r)),
                   "cut_mid_run": sum(1 for r in kr if r.get("cut_mid_run") is True), "points": ["%s/%s" % x for x in pts],
                   "distinct": len(set(pts)) == len(pts), "first": POWEROFF_FIRST in [p for (p, _) in pts]}
declared = list(((results(cr_run).get("fault_points") or {}).get("declared")) or (cr_mx or {}).get("points") or [])
gate_points = sorted({p for (p, _, _, _) in GATE_POINTS})
listed = [fp.get("point") for fp in (cases.get("crash") or {}).get("fault_points") or []]
k13 = {"planned": len(GATE_ROUNDS), "rows": len(abort), "unreached": unreached, "failing": failing,
       "poweroff": po_kinds, "poweroff_want_per_kind": POWEROFF_PER_KIND,
       "poweroff_consistent": sum(v["consistent"] for v in po_kinds.values()), "poweroff_total_want": POWEROFF_PER_KIND * len(KINDS),
       "declared_points": declared,
       "declared_not_in_gate": [p for p in declared if p not in gate_points and p not in NOT_REACHABLE],
       "gate_not_declared": [p for p in gate_points if declared and p not in declared],
       "declared_not_in_cases": [p for p in declared if p not in listed],
       "subset_run": bool((cr_mx or {}).get("kinds") or (cr_mx or {}).get("filter_points")), "run_phases_ok": phases_ok(cr_run)}
k13["pass"] = bool(GATE_ROUNDS and not unreached and not failing and declared and not k13["declared_not_in_gate"]
                   and not k13["gate_not_declared"] and not k13["declared_not_in_cases"]
                   and all(v["rounds"] == POWEROFF_PER_KIND and v["consistent"] == POWEROFF_PER_KIND and v["distinct"] and v["first"]
                           for v in po_kinds.values())
                   and not k13["subset_run"] and k13["run_phases_ok"])

# ---------------------------------------------------------------------------------------------- E1 elevated tests
got_el = {(t.get("crate"), t.get("test")): t for t in (el or {}).get("targets") or [] if t}
el_rows = []
for w in ELEVATED:
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
        if len(passed) < w["min"]:
            probs.append("%d passed, want at least %s" % (len(passed), w["min"]))
        pre = w.get("require_prefix") or ""
        if pre and sum(1 for n in passed if n.startswith(pre)) < w["prefix_min"]:
            probs.append("fewer than %s passing %s tests" % (w["prefix_min"], pre))
    for n in w.get("require_names") or []:
        if not any(p == n or p.endswith("::" + n) for p in passed):
            probs.append("%s did not pass" % n)
    el_rows.append({"crate": w["crate"], "test": w["test"], "passed": len(passed), "problems": probs, "pass": not probs})
e1 = {"targets": el_rows, "admin": bool((el or {}).get("admin"))}
e1["pass"] = bool(el_rows and e1["admin"] and all(r["pass"] for r in el_rows))

# ---------------------------------------------------------------------------------------------- report
crit = {"BIND": binding, "K10": k10, "K11": k11, "K12": k12, "K13": k13, "E1": e1}
failing_crit = [k for k, v in crit.items() if not v.get("pass")]
report = {
    "schema": "purge.rig.m1b-exec-score/2", "written": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "runs_dir": runs_dir, "prefix": prefix, "cases": cases_path, "ambient": ambient_path, "missing": missing,
    "gates": {"G5": {"criteria": ["BIND", "K10", "K11", "K12"], "pass": not missing and all(crit[k]["pass"] for k in ("BIND", "K10", "K11", "K12"))},
              "G6": {"criteria": ["BIND", "K13", "E1"], "pass": not missing and all(crit[k]["pass"] for k in ("BIND", "K13", "E1"))}},
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
