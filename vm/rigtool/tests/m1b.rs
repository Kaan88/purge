//! M1b (M1B-RIGTOOL) checks of the rigtool binary, driven through its command line with fixture files:
//! `score` protected_correct, `traps`, `fidelity` on typed objects, `execdiff` typed collateral and the journal's
//! M1b records.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("rigtool-m1b-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }
    fn json(&self, name: &str, v: &Value) -> PathBuf {
        self.file(name, &serde_json::to_string_pretty(v).unwrap())
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// (exit code, stderr).
fn rigtool(args: &[&dyn AsRef<std::ffi::OsStr>]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rigtool")).args(args.iter().map(|a| a.as_ref())).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn read(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

const SVC: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
const FW: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";
const TC: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
const TASKS: &str = "C:\\Windows\\System32\\Tasks";

// ---------------------------------------------------------------------------------------------
// Snapshots (`#purge-snap 1` text)
// ---------------------------------------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
}

fn snap(lines: &[String]) -> String {
    let roots = ["HKLM\\SOFTWARE", "HKLM\\SYSTEM", "C:\\Windows\\System32\\Tasks", "C:\\ProgramData"];
    let mut s = String::from("#purge-snap 1\t2026-11-17T10:00:00Z\tPC\tPro\t26100\n#roots");
    for r in roots {
        s.push('\t');
        s.push_str(&esc(r));
    }
    s.push('\n');
    for l in lines {
        s.push_str(l);
    }
    s
}

fn k(key: &str) -> String {
    format!("K\t{}\t1\t\t\n", esc(key))
}

fn v(key: &str, name: &str, typ: u32, len: u32, hash: u64, preview: &str) -> String {
    format!("V\t{}\t{}\t{typ}\t{len}\t{hash:016x}\t{}\n", esc(key), esc(name), esc(preview))
}

fn f(path: &str, size: u64, mtime: u64) -> String {
    format!("F\t{}\t{size}\t20\t{mtime}\t0\n", esc(path))
}

fn d(path: &str) -> String {
    format!("D\t{}\t10\t1\t0\n", esc(path))
}

// ---------------------------------------------------------------------------------------------
// Journal and report (purge-model shapes)
// ---------------------------------------------------------------------------------------------

const SESSION: &str = "20261117T100000Z-0123456789abcdef";
const HA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const HB: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

fn header(items: usize) -> Value {
    json!({"rec": "header", "schema": "purge.journal/1", "session": SESSION, "created": 134078121020000000u64,
        "engine_version": "0.2.0", "app": "fixture", "plan_hash": HA, "selection_hash": HB,
        "policy_version": "m1b", "mode": "post", "items": items, "allow_irreversible": false,
        "volumes": [{"root": "C:\\", "serial": 1, "file_system": "NTFS",
            "quarantine": format!("C:\\ProgramData\\Purge\\Quarantine\\{SESSION}")}]})
}

/// (target, exec_op, inverse) of an M1b object op.
fn obj_parts(op: u32, kind: &str, a: &str) -> (Value, Value, Value, &'static str) {
    let def = json!({"path": format!("def\\{op:06}.json"), "sha256": HA, "bytes": 300});
    match kind {
        "DeleteService" => (
            json!({"type": "Service", "name": a}),
            json!({"kind": kind, "name": a}),
            json!({"kind": "RecreateService", "definition": def}),
            "service",
        ),
        "DeleteTask" => (
            json!({"type": "Task", "path": a}),
            json!({"kind": kind, "path": a}),
            json!({"kind": "RecreateTask", "definition": def}),
            "task",
        ),
        "DeleteFirewallRule" => (
            json!({"type": "FirewallRule", "id": a}),
            json!({"kind": kind, "id": a}),
            json!({"kind": "RecreateFirewallRule", "definition": def}),
            "firewall_rule",
        ),
        k => panic!("{k}"),
    }
}

/// validated (with M1b `exemptions`), intent, done records of one object op; `facts_kind` overrides the
/// object kind of the facts.
fn obj_op(op: u32, kind: &str, a: &str, outcome: Value, facts_kind: Option<&str>) -> Vec<Value> {
    let item = format!("c-{op:02}");
    let (target, exec_op, inverse, ok) = obj_parts(op, kind, a);
    let facts = json!({"kind": "Object", "object_kind": facts_kind.unwrap_or(ok), "sha256": HB, "running": false});
    vec![
        json!({"rec": "validated", "op": op, "item": item, "target": target, "facts": facts, "exemptions": []}),
        json!({"rec": "intent", "op": op, "item": item, "exec_op": exec_op, "inverse": inverse, "pre": facts}),
        json!({"rec": "done", "op": op, "item": item, "outcome": outcome}),
    ]
}

fn counts(outcomes: &[&Value]) -> Value {
    let mut c = json!({"done": 0, "vanished": 0, "skipped": 0, "held_retry": 0, "pending_reboot": 0, "failed": 0});
    for o in outcomes {
        let k = match o["kind"].as_str().unwrap() {
            "Done" => "done",
            "PendingDelete" | "PendingReboot" => "pending_reboot",
            "Skipped" => "skipped",
            "Failed" => "failed",
            x => panic!("{x}"),
        };
        c[k] = json!(c[k].as_u64().unwrap() + 1);
    }
    c
}

/// A journal (header, the ops' records, `extra` records, commit) and the matching `purge.exec/1` report.
fn journal_and_report(ops: &[(u32, &str, &str, Value)], extra: &[Value]) -> (String, String) {
    let mut s = format!("{}\n", header(ops.len()));
    for (op, kind, a, o) in ops {
        for r in obj_op(*op, kind, a, o.clone(), None) {
            s.push_str(&format!("{r}\n"));
        }
    }
    for r in extra {
        s.push_str(&format!("{r}\n"));
    }
    let c = counts(&ops.iter().map(|x| &x.3).collect::<Vec<_>>());
    s.push_str(&format!("{}\n", json!({"rec": "commit", "at": 134078121950000000u64, "counts": c, "backup_bytes": 0})));
    let items: Vec<Value> = ops
        .iter()
        .map(|(op, kind, a, o)| {
            let (target, exec_op, _, _) = obj_parts(*op, kind, a);
            json!({"item": format!("c-{op:02}"), "op": op, "target": target, "exec_op": exec_op, "outcome": o,
                "backup_bytes": 0})
        })
        .collect();
    let rep = json!({"schema": "purge.exec/1", "session": SESSION, "app": "fixture", "plan_hash": HA,
        "selection_hash": HB, "state": "Committed", "started": 1, "finished": 2, "items": items, "counts": c,
        "backup_bytes": 0, "pending_reboot": false, "restore_point": {"kind": "NotRequested"}, "warnings": []});
    (s, rep.to_string())
}

// ---------------------------------------------------------------------------------------------
// Deep documents (`purge.rig.deep/1`)
// ---------------------------------------------------------------------------------------------

fn dv(name: &str, typ: u32, len: u32, sha: &str) -> Value {
    json!({"name": name, "type": typ, "len": len, "sha256": sha})
}

fn dkey(key: &str, values: Vec<Value>) -> Value {
    json!({"key": key, "present": true, "sddl": "O:BAG:SYD:(A;;KA;;;BA)", "is_link": false, "values": values})
}

fn deep(files: Vec<Value>, keys: Vec<Value>, objects: Vec<Value>) -> Value {
    json!({"schema": "purge.rig.deep/1", "time": "2026-11-17T10:00:00Z", "computer": "PC", "build": "26100",
        "scope": {}, "files": files, "keys": keys, "objects": objects, "errors": 0})
}

/// Runs `fidelity`; (exit code, stderr, report).
fn fidelity(dir: &Dir, tag: &str, before: &Value, after: &Value, journal: &str) -> (i32, String, Value) {
    let (b, a) = (dir.json(&format!("{tag}-before.json"), before), dir.json(&format!("{tag}-after.json"), after));
    let j = dir.file(&format!("{tag}-journal.jsonl"), journal);
    let out = dir.path(&format!("{tag}-fidelity.json"));
    let (code, err) = rigtool(&[&"fidelity", &"--before", &b, &"--after", &a, &"--journal", &j, &"-o", &out]);
    let rep = if out.exists() { read(&out) } else { Value::Null };
    (code, err, rep)
}

fn row<'a>(rep: &'a Value, action: &str) -> &'a Value {
    rep["rows"].as_array().unwrap().iter().find(|r| r["action"] == action).unwrap_or_else(|| panic!("{action}"))
}

// ---------------------------------------------------------------------------------------------
// score: protected_correct (C-RIG)
// ---------------------------------------------------------------------------------------------

const SHARED_A: &str = "HKLM\\SOFTWARE\\Shared\\A";
const SHARED_B: &str = "HKLM\\SOFTWARE\\Shared\\B";
const SHARED_C: &str = "HKLM\\SOFTWARE\\Shared\\C\\Sub";
const VENDOR: &str = "HKLM\\SOFTWARE\\Vendor";

/// Runs `score` over one plan; the tool's score object.
fn score(dir: &Dir, truth: &[(&str, &str)], plan: &[(&str, &str, bool)]) -> Value {
    let keys: Vec<&str> = truth.iter().map(|t| t.0).chain(plan.iter().map(|p| p.0)).collect();
    let s0 = dir.file("s0.tsv", &snap(&[k("HKLM\\SOFTWARE")]));
    let mut lines = vec![k("HKLM\\SOFTWARE")];
    lines.extend(keys.iter().map(|x| k(x)));
    let s2 = dir.file("s2.tsv", &snap(&lines));
    let items: Vec<Value> = truth
        .iter()
        .map(|(p, l)| json!({"target": {"type": "RegKey", "path": p}, "label": l, "rule": "fixture"}))
        .collect();
    let t = dir.json("truth.json", &json!({"schema": "purge.rig.truth/1", "id": "fixture", "items": items}));
    let pitems: Vec<Value> = plan
        .iter()
        .map(|(p, b, pre)| {
            json!({"target": {"type": "RegKey", "path": p}, "band": b, "preselected": pre, "scanner": "S"})
        })
        .collect();
    let p = dir.json(
        "plan.json",
        &json!({"schema": "purge.plan/0", "app": "fixture", "tool": "purge", "mode": "post", "items": pitems}),
    );
    let out = dir.path("score.json");
    let (code, err) = rigtool(&[&"score", &"--plan", &p, &"--truth", &t, &"--s0", &s0, &"--s2", &s2, &"--json", &out]);
    assert_eq!(code, 0, "{err}");
    read(&out)["apps"][0]["tools"][0].clone()
}

#[test]
fn protected_correct_counts_listed_protected_as_correct() {
    let dir = Dir::new("pc-listed");
    // A listed as Protected (Blocked), B not listed, C inside a Protected key: all three correct.
    let s = score(
        &dir,
        &[(SHARED_A, "kept_owner"), (SHARED_B, "kept_owner"), (SHARED_C, "kept_owner"), (VENDOR, "leftover")],
        &[(SHARED_A, "Blocked", false), ("HKLM\\SOFTWARE\\Shared\\C", "Blocked", false), (VENDOR, "Safe", true)],
    );
    assert_eq!(s["protected_n"], 3, "{s:#}");
    assert_eq!(s["protected_correct_n"], 3);
    assert_eq!(s["protected_correct"], 1.0);
    assert_eq!(s["protected_correct_pct"], 100.0);
    assert_eq!(s["protected_wrong"], json!([]));
}

#[test]
fn protected_correct_null_when_no_items() {
    let dir = Dir::new("pc-null");
    let s = score(&dir, &[(VENDOR, "leftover")], &[(VENDOR, "Safe", true)]);
    assert_eq!(s["protected_n"], 0, "{s:#}");
    // Not applicable: null, never 1.0 (a pass) or 0.
    assert!(s.get("protected_correct").is_some_and(Value::is_null), "{s:#}");
    assert!(s.get("protected_correct_pct").is_some_and(Value::is_null), "{s:#}");
}

#[test]
fn protected_correct_listed_likely_is_wrong() {
    let dir = Dir::new("pc-likely");
    // A listed Likely (not even preselected): wrong. B not listed: correct. C covered by a Weak ancestor: wrong.
    let s = score(
        &dir,
        &[(SHARED_A, "kept_owner"), (SHARED_B, "kept_owner"), (SHARED_C, "kept_owner")],
        &[(SHARED_A, "Likely", false), ("HKLM\\SOFTWARE\\Shared\\C", "Weak", false)],
    );
    assert_eq!(s["protected_n"], 3, "{s:#}");
    assert_eq!(s["protected_correct_n"], 1);
    assert_eq!(s["protected_correct_pct"], 33.33);
    let wrong = s["protected_wrong"].as_array().unwrap();
    assert_eq!(wrong.len(), 2, "{wrong:#?}");
    let a = wrong.iter().find(|w| w["target"].as_str().unwrap().ends_with("\\Shared\\A")).unwrap();
    assert_eq!((a["relation"].as_str(), a["band"].as_str()), (Some("equal"), Some("Likely")));
    let c = wrong.iter().find(|w| w["target"].as_str().unwrap().ends_with("\\C\\Sub")).unwrap();
    assert_eq!((c["relation"].as_str(), c["band"].as_str()), (Some("covers"), Some("Weak")));
}

// ---------------------------------------------------------------------------------------------
// traps
// ---------------------------------------------------------------------------------------------

fn case(id: &str, expect: Vec<Value>) -> Value {
    json!({"id": id, "phase": "post", "plant": format!("plant {id}"), "expect": expect})
}

fn ex(target: Value, verdict: &str, blocker: Option<&str>) -> Value {
    json!({"target": target, "verdict": verdict, "blocker": blocker})
}

fn key(p: &str) -> Value {
    json!({"type": "RegKey", "path": p})
}

/// A `purge.scan/0` candidate.
fn cand(target: Value, band: Option<&str>, pre: bool, blockers: &[&str]) -> Value {
    json!({"id": "x", "target": target, "action": "DeleteKey",
        "blockers": blockers.iter().map(|b| json!({"kind": b})).collect::<Vec<_>>(),
        "decision": band.map(|b| json!({"band": b, "preselected": pre, "score": 0, "explanation": []})),
        "children": []})
}

/// Runs `traps`; (exit code, stderr, output or null).
fn traps(dir: &Dir, tag: &str, plan: &Value, cases: &[Value], app: &str) -> (i32, String, Value) {
    let p = dir.json(&format!("{tag}-plan.json"), plan);
    let t = dir.json(&format!("{tag}-traps.json"), &json!({"schema": "purge.m1b.traps/1", "cases": cases}));
    let out = dir.path(&format!("{tag}-out.json"));
    let _ = std::fs::remove_file(&out);
    let (code, err) = rigtool(&[&"traps", &"--plan", &p, &"--traps", &t, &"--app", &app, &"--out", &out]);
    (code, err, if out.exists() { read(&out) } else { Value::Null })
}

fn result_of<'a>(out: &'a Value, id: &str) -> &'a str {
    let c = out["cases"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap();
    c["expectations"][0]["result"].as_str().unwrap()
}

#[test]
fn traps_absent_escape_when_ancestor_listed() {
    let dir = Dir::new("traps-absent");
    let clsid = "HKLM\\SOFTWARE\\Classes\\CLSID\\{0A1B2C3D-0000-4000-8000-00000000C0DE}";
    // Hostile: no plan item names a trap target, yet deleting the listed ancestors takes each one with it.
    let plan = json!({"schema": "purge.scan/0", "app": "fixture", "items": [
        cand(key(clsid), Some("Weak"), false, &[]),
        cand(json!({"type": "Path", "path": "C:\\ProgramData\\Vendor"}), Some("Safe"), true, &[]),
        cand(key(SVC), Some("Likely"), false, &[]),
        cand(key(VENDOR), Some("Safe"), true, &[]),
    ], "absorbed": []});
    let cases = [
        case("com-shared", vec![ex(key(&format!("{clsid}\\InprocServer32")), "absent", None)]),
        case(
            "file-shared",
            vec![ex(json!({"type": "Path", "path": "C:\\ProgramData\\Vendor\\shared\\keep.dll"}), "absent", None)],
        ),
        case("svc-shared", vec![ex(json!({"type": "Service", "name": "PurgeTrapShared"}), "absent", None)]),
        // Control: a name that only starts like a listed key is not inside it.
        case("prefix-sibling", vec![ex(key("HKLM\\SOFTWARE\\VendorTools"), "absent", None)]),
    ];
    let (code, err, out) = traps(&dir, "a", &plan, &cases, "fixture");
    assert_eq!(code, 1, "{err}");
    assert_eq!(out["summary"]["escapes"], 3, "{out:#}");
    assert_eq!(out["summary"]["missed_owned"], 0);
    assert_eq!(result_of(&out, "com-shared"), "escape");
    assert_eq!(result_of(&out, "file-shared"), "escape");
    assert_eq!(result_of(&out, "svc-shared"), "escape");
    assert_eq!(result_of(&out, "prefix-sibling"), "pass");
    let l = &out["cases"][0]["expectations"][0]["listings"][0];
    assert_eq!(l["relation"], "covers", "{l:#}");
}

#[test]
fn traps_protected_requires_named_blocker() {
    let dir = Dir::new("traps-protected");
    let svc = json!({"type": "Service", "name": "PurgeTrapShared"});
    let scan = |blockers: &[&str]| json!({"schema": "purge.scan/0", "app": "fixture", "items": [cand(svc.clone(), Some("Blocked"), false, blockers)]});
    let want = |b: &str| [case("svc-shared", vec![ex(svc.clone(), "protected", Some(b))])];
    // Protected with the named blocker: pass.
    let (code, err, out) = traps(&dir, "ok", &scan(&["SharedRefcount"]), &want("SharedRefcount"), "fixture");
    assert_eq!(code, 0, "{err}\n{out:#}");
    assert_eq!(out["summary"]["escapes"], 0);
    // Protected, but for another reason: escape.
    let (code, _, out) = traps(&dir, "other", &scan(&["ServiceRunning"]), &want("SharedRefcount"), "fixture");
    assert_eq!(code, 1);
    assert_eq!(result_of(&out, "svc-shared"), "escape", "{out:#}");
    // A plan document that records no blockers cannot show the named one: escape, not a pass.
    let plan0 = json!({"schema": "purge.plan/0", "app": "fixture", "items": [
        {"target": svc, "band": "Blocked", "preselected": false}]});
    let (code, _, out) = traps(&dir, "plan0", &plan0, &want("SharedRefcount"), "fixture");
    assert_eq!(code, 1);
    assert_eq!(result_of(&out, "svc-shared"), "escape", "{out:#}");
}

#[test]
fn traps_listed_missing_is_missed_owned() {
    let dir = Dir::new("traps-listed");
    let owned = json!({"type": "Service", "name": "PurgeTrapOwned"});
    let task = json!({"type": "Task", "path": "\\PurgeTrap\\Owned"});
    let plan = json!({"schema": "purge.scan/0", "app": "fixture", "items": [
        cand(task.clone(), Some("Blocked"), false, &["ServiceRunning"]),
    ]});
    let cases =
        [case("svc-owned", vec![ex(owned, "listed", None)]), case("task-owned", vec![ex(task, "listed", None)])];
    let (code, err, out) = traps(&dir, "m", &plan, &cases, "fixture");
    assert_eq!(code, 1, "{err}");
    assert_eq!(out["summary"]["missed_owned"], 2, "{out:#}");
    assert_eq!(out["summary"]["escapes"], 0);
    assert_eq!(result_of(&out, "svc-owned"), "missed_owned");
    // Listed only as Protected is not listed for removal.
    assert_eq!(result_of(&out, "task-owned"), "missed_owned");
}

#[test]
fn traps_empty_file_is_error() {
    let dir = Dir::new("traps-empty");
    let plan = json!({"schema": "purge.scan/0", "app": "fixture", "items": []});
    let (code, err, out) = traps(&dir, "empty", &plan, &[], "fixture");
    assert_eq!(code, 2, "{err}");
    assert!(out.is_null(), "no result for an empty trap file");
    assert!(err.contains("zero cases"), "{err}");
    // A case without expectations, and a plan of another app: errors as well.
    let (code, _, _) = traps(&dir, "noexp", &plan, &[case("x", vec![])], "fixture");
    assert_eq!(code, 2);
    let one = [case("x", vec![ex(key(VENDOR), "absent", None)])];
    let (code, err, out) = traps(&dir, "app", &plan, &one, "another-app");
    assert_eq!(code, 2, "{err}");
    assert!(out.is_null());
    // The same inputs with the right app pass (exit 0): the errors above come from the checks.
    let (code, err, _) = traps(&dir, "right", &plan, &one, "fixture");
    assert_eq!(code, 0, "{err}");
}

// ---------------------------------------------------------------------------------------------
// fidelity: typed objects
// ---------------------------------------------------------------------------------------------

#[test]
fn fidelity_service_detects_changed_value_type() {
    let dir = Dir::new("fid-svc");
    let key = format!("{SVC}\\PurgeTrapSvc");
    let keys = |start_type: u32| {
        vec![
            dkey(&key, vec![dv("ImagePath", 2, 60, HA), dv("Start", start_type, 4, HB), dv("Type", 4, 4, HA)]),
            dkey(&format!("{key}\\Security"), vec![dv("Security", 3, 120, HA)]),
        ]
    };
    let (j, _) = journal_and_report(&[(1, "DeleteService", "PurgeTrapSvc", json!({"kind": "Done"}))], &[]);
    // Restored exactly: pass.
    let (code, err, rep) = fidelity(&dir, "same", &deep(vec![], keys(4), vec![]), &deep(vec![], keys(4), vec![]), &j);
    assert_eq!(code, 0, "{err}");
    assert_eq!(row(&rep, "DeleteService")["pass"], true, "{rep:#}");
    // `Start` came back as REG_BINARY with the same bytes: a difference, the row fails.
    let (code, err, rep) = fidelity(&dir, "type", &deep(vec![], keys(4), vec![]), &deep(vec![], keys(3), vec![]), &j);
    assert_eq!(code, 1, "{err}");
    assert_eq!(row(&rep, "DeleteService")["pass"], false);
    let d = rep["differences"].as_array().unwrap();
    assert_eq!(d.len(), 1, "{d:#?}");
    assert!(d[0]["object"].as_str().unwrap().ends_with("PurgeTrapSvc|Start"));
    assert_eq!(d[0]["fields"][0]["field"], "type");
    assert!(
        err.lines().any(|l| l.starts_with("fidelity: difference: DeleteService") && l.contains("Start type")),
        "{err}"
    );
}

#[test]
fn fidelity_firewall_ignores_field_order_only() {
    let dir = Dir::new("fid-fw");
    let id = "{5B7F0E1A-0000-4000-8000-0000000F1AE0}";
    let before_rule = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|Name=Trap|";
    let fw = |rule: &str, sha: &str| {
        let mut kx = dkey(FW, vec![dv(id, 1, (rule.len() * 2 + 2) as u32, sha)]);
        kx["only_values"] = json!([id]);
        deep(vec![], vec![kx], vec![json!({"kind": "firewall_rule", "id": id, "present": true, "rule": rule})])
    };
    let (j, _) = journal_and_report(&[(1, "DeleteFirewallRule", id, json!({"kind": "Done"}))], &[]);
    // Same fields, another order (the value's bytes and hash differ): identical, the normalisation is printed.
    let reordered = "v2.33|Dir=In|Action=Allow|LPort=8080|Protocol=6|Active=TRUE|Name=Trap|";
    let (code, err, rep) = fidelity(&dir, "order", &fw(before_rule, HA), &fw(reordered, HB), &j);
    assert_eq!(code, 0, "{err}\n{rep:#}");
    assert_eq!(row(&rep, "DeleteFirewallRule")["pass"], true);
    assert!(rep["differences"].as_array().unwrap().is_empty(), "{rep:#}");
    let n = rep["normalisations"].as_array().unwrap();
    assert!(n.iter().any(|x| x.as_str().unwrap().contains("field order")), "{n:#?}");
    assert!(err.contains("fidelity: normalised:"), "{err}");
    // One field changed: a difference.
    let changed = "v2.33|Dir=Out|Action=Allow|LPort=8080|Protocol=6|Active=TRUE|Name=Trap|";
    let (code, err, rep) = fidelity(&dir, "changed", &fw(before_rule, HA), &fw(changed, HB), &j);
    assert_eq!(code, 1, "{err}");
    let d = &rep["differences"].as_array().unwrap()[0];
    assert_eq!(d["fields"][0]["field"], "rule.fields", "{d:#}");
    assert_eq!(d["fields"][0]["before"], json!(["Dir=In"]));
    assert_eq!(d["fields"][0]["after"], json!(["Dir=Out"]));
    // A field key in another case is another field (no case folding).
    let cased = "v2.33|dir=In|Action=Allow|LPort=8080|Protocol=6|Active=TRUE|Name=Trap|";
    let (code, _, _) = fidelity(&dir, "case", &fw(before_rule, HA), &fw(cased, HB), &j);
    assert_eq!(code, 1);
}

#[test]
fn fidelity_task_applies_only_listed_normalisations() {
    let dir = Dir::new("fid-task");
    let path = "\\PurgeTrap\\Update";
    let file = format!("{TASKS}\\PurgeTrap\\Update");
    let tree = format!("{TC}\\Tree\\PurgeTrap\\Update");
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<Task version=\"1.2\"><Actions /></Task>";
    let sddl = "O:BAG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)";
    #[allow(clippy::too_many_arguments)]
    fn doc(
        file: &str,
        tree: &str,
        path: &str,
        fsha: &str,
        fsize: u64,
        sd: (u32, u32, &str),
        x: &str,
        s: &str,
    ) -> Value {
        deep(
            vec![json!({"path": file, "present": true, "is_dir": false, "attributes": "0x20", "size": fsize,
                "sha256": fsha, "sddl": "O:BAG:SYD:(A;;FA;;;BA)"})],
            vec![dkey(tree, vec![dv("SD", sd.0, sd.1, sd.2), dv("Extra", 4, 4, HA)])],
            vec![json!({"kind": "task", "id": path, "present": true, "xml": x, "sddl": s})],
        )
    }
    let before = doc(&file, &tree, path, HA, 3000, (3, 140, HA), xml, sddl);
    let (j, _) = journal_and_report(&[(1, "DeleteTask", path, json!({"kind": "Done"}))], &[]);
    // Re-registered: the file is rewritten and Tree|SD regenerated (both listed by the spike), XML and SDDL equal.
    let after = doc(&file, &tree, path, HB, 3012, (3, 156, HB), xml, sddl);
    let (code, err, rep) = fidelity(&dir, "listed", &before, &after, &j);
    assert_eq!(code, 0, "{err}\n{rep:#}");
    assert_eq!(row(&rep, "DeleteTask")["pass"], true);
    let n: Vec<&str> = rep["normalisations"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert_eq!(n.len(), 2, "{n:#?}");
    assert!(n.iter().any(|x| x.contains("Tree|SD") && x.contains("taskcache_regenerated")), "{n:#?}");
    assert!(n.iter().any(|x| x.contains("file") && x.contains("sha256")), "{n:#?}");
    assert_eq!(err.matches("fidelity: normalised:").count(), 2, "{err}");
    // Not listed: XML that differs only in white space, a changed SDDL, SD with another type, another Tree value.
    let fails = [
        ("xml", doc(&file, &tree, path, HB, 3012, (3, 156, HB), &xml.replace('\n', "\r\n"), sddl)),
        ("sddl", doc(&file, &tree, path, HB, 3012, (3, 156, HB), xml, "O:BAG:SYD:(A;;FA;;;BA)")),
        ("sd-type", doc(&file, &tree, path, HB, 3012, (4, 156, HB), xml, sddl)),
    ];
    for (tag, after) in fails {
        let (code, err, rep) = fidelity(&dir, tag, &before, &after, &j);
        assert_eq!(code, 1, "{tag}: {err}");
        assert_eq!(row(&rep, "DeleteTask")["pass"], false, "{tag}");
    }
    let mut extra = after.clone();
    extra["keys"][0]["values"][1]["sha256"] = json!(HB);
    let (code, _, rep) = fidelity(&dir, "extra", &before, &extra, &j);
    assert_eq!(code, 1, "{rep:#}");
    // Without the task's own record after the undo: a difference, never a silent pass.
    let mut gone = after.clone();
    gone["objects"] = json!([]);
    let (code, _, _) = fidelity(&dir, "gone", &before, &gone, &j);
    assert_eq!(code, 1);
}

// ---------------------------------------------------------------------------------------------
// execdiff: typed collateral
// ---------------------------------------------------------------------------------------------

const TASK_ID: &str = "{11111111-2222-4333-8444-555555555555}";
const RULE: &str = "{5B7F0E1A-0000-4000-8000-0000000F1AE0}";

/// The before state: a service with a subkey, two firewall rules, a task with its TaskCache entries, a neighbour
/// service and a service whose name extends the deleted one's.
fn exec_before() -> Vec<String> {
    let svc = format!("{SVC}\\PurgeTrapSvc");
    let tree = format!("{TC}\\Tree\\PurgeTrap\\Update");
    vec![
        k(SVC),
        k(&svc),
        v(&svc, "ImagePath", 2, 60, 1, "C:\\Vendor\\svc.exe"),
        k(&format!("{svc}\\Parameters")),
        v(&format!("{svc}\\Parameters"), "Port", 4, 4, 2, "80"),
        k(&format!("{SVC}\\PurgeTrapSvcX")),
        v(&format!("{SVC}\\PurgeTrapSvcX"), "Start", 4, 4, 3, "3"),
        k(&format!("{SVC}\\OtherSvc")),
        v(&format!("{SVC}\\OtherSvc"), "Start", 4, 4, 4, "2"),
        k(FW),
        v(FW, RULE, 1, 100, 5, "v2.33|Action=Allow|"),
        v(FW, "{OTHER-RULE}", 1, 100, 6, "v2.33|Action=Block|"),
        k(TC),
        k(&format!("{TC}\\Tree")),
        k(&format!("{TC}\\Tree\\PurgeTrap")),
        k(&tree),
        v(&tree, "Id", 1, 78, 7, TASK_ID),
        v(&tree, "Index", 4, 4, 8, "3"),
        v(&tree, "SD", 3, 140, 9, ""),
        k(&format!("{TC}\\Tasks")),
        k(&format!("{TC}\\Tasks\\{TASK_ID}")),
        v(&format!("{TC}\\Tasks\\{TASK_ID}"), "Path", 1, 40, 10, "\\PurgeTrap\\Update"),
        v(&format!("{TC}\\Tasks\\{TASK_ID}"), "Hash", 3, 32, 11, ""),
        v(&format!("{TC}\\Tasks\\{TASK_ID}"), "Triggers", 3, 72, 12, ""),
        v(&format!("{TC}\\Tasks\\{TASK_ID}"), "DynamicInfo", 3, 36, 13, ""),
        k(&format!("{TC}\\Plain")),
        k(&format!("{TC}\\Plain\\{TASK_ID}")),
        d(TASKS),
        d(&format!("{TASKS}\\PurgeTrap")),
        f(&format!("{TASKS}\\PurgeTrap\\Update"), 3000, 5),
    ]
}

/// Runs `execdiff`; (exit code, stderr, report).
fn execdiff(
    dir: &Dir,
    tag: &str,
    before: &[String],
    after: &[String],
    ops: &[(u32, &str, &str, Value)],
) -> (i32, String, Value) {
    let (j, r) = journal_and_report(ops, &[]);
    let (a, b) = (dir.file(&format!("{tag}-a.tsv"), &snap(before)), dir.file(&format!("{tag}-b.tsv"), &snap(after)));
    let (jp, rp) = (dir.file(&format!("{tag}-j.jsonl"), &j), dir.file(&format!("{tag}-r.json"), &r));
    let out = dir.path(&format!("{tag}-execdiff.json"));
    let (code, err) =
        rigtool(&[&"execdiff", &"--before", &a, &"--after", &b, &"--journal", &jp, &"--report", &rp, &"-o", &out]);
    (code, err, if out.exists() { read(&out) } else { Value::Null })
}

fn removed(lines: &[String], gone: &[&str]) -> Vec<String> {
    // Drops every K/V/F/D line whose path field is at or under one of `gone` (exact path for F/D) or, for an
    // entry "key|name", that one value.
    lines
        .iter()
        .filter(|l| {
            let mut it = l.split('\t');
            let rec = it.next().unwrap();
            let p = it.next().unwrap().replace("\\\\", "\\");
            let name = if rec == "V" { it.next().map(|n| n.replace("\\\\", "\\")) } else { None };
            !gone.iter().any(|g| match g.split_once('|') {
                Some((gk, gn)) => rec == "V" && p.eq_ignore_ascii_case(gk) && name.as_deref() == Some(gn),
                None => {
                    let (pl, gl) = (p.to_ascii_lowercase(), g.to_ascii_lowercase());
                    pl == gl || pl.starts_with(&format!("{gl}\\"))
                }
            })
        })
        .cloned()
        .collect()
}

#[test]
fn execdiff_typed_collateral_counted() {
    let dir = Dir::new("execdiff");
    let before = exec_before();
    let svc = format!("{SVC}\\PurgeTrapSvc");
    let ops = [
        (1, "DeleteService", "PurgeTrapSvc", json!({"kind": "Done"})),
        (2, "DeleteFirewallRule", RULE, json!({"kind": "Done"})),
        (3, "DeleteTask", "\\PurgeTrap\\Update", json!({"kind": "Done"})),
    ];
    let planned_gone: Vec<String> = vec![
        svc.clone(),
        format!("{FW}|{RULE}"),
        format!("{TC}\\Tree\\PurgeTrap\\Update"),
        format!("{TC}\\Tasks\\{TASK_ID}"),
        format!("{TC}\\Plain\\{TASK_ID}"),
        format!("{TASKS}\\PurgeTrap\\Update"),
    ];
    let gone: Vec<&str> = planned_gone.iter().map(String::as_str).collect();
    // Only the planned objects gone: no collateral.
    let clean = removed(&before, &gone);
    let (code, err, rep) = execdiff(&dir, "clean", &before, &clean, &ops);
    assert_eq!(rep["counts"]["collateral"], 0, "{err}\n{rep:#}");
    assert_eq!(code, 0, "{err}\n{rep:#}");
    assert!(rep["counts"]["authorised"]["op"].as_u64().unwrap() >= 10, "{rep:#}");
    let effects = rep["effects"].as_array().unwrap();
    assert!(effects.iter().all(|e| e["verdict"] == "ok"), "{effects:#?}");
    // Beyond them: the other firewall rule, a neighbour's value, the service whose name extends the deleted one's.
    let (other_rule, svc_x) = (format!("{FW}|{{OTHER-RULE}}"), format!("{SVC}\\PurgeTrapSvcX"));
    let mut extra = gone.clone();
    extra.extend([other_rule.as_str(), svc_x.as_str()]);
    let mut after = removed(&before, &extra);
    after.retain(|l| !l.contains("OtherSvc\tStart"));
    after.push(v(&format!("{SVC}\\OtherSvc"), "Start", 4, 4, 99, "4"));
    let (code, err, rep) = execdiff(&dir, "collateral", &before, &after, &ops);
    assert_eq!(code, 1, "{err}");
    assert_eq!(rep["counts"]["collateral"], 4, "{rep:#}");
    let rows: Vec<String> = rep["collateral"].as_array().unwrap().iter().map(|r| r.to_string()).collect();
    assert!(rows.iter().any(|r| r.contains("OTHER-RULE")), "{rows:#?}");
    assert!(rows.iter().any(|r| r.contains("OtherSvc")), "{rows:#?}");
    assert!(rows.iter().any(|r| r.contains("PurgeTrapSvcX")), "{rows:#?}");
}

#[test]
fn execdiff_task_reregistration_only_listed_values() {
    let dir = Dir::new("execdiff-rereg");
    let before = exec_before();
    let tree = format!("{TC}\\Tree\\PurgeTrap\\Update");
    let tasks = format!("{TC}\\Tasks\\{TASK_ID}");
    let ops =
        [(1, "DeleteTask", "\\PurgeTrap\\Update", json!({"kind": "Skipped", "reason": {"kind": "ChangedSinceScan"}}))];
    // The task was registered again (same Id): SD, DynamicInfo, Hash and Triggers (same length) regenerated.
    let rereg = |triggers_len: u32, index: u64| -> Vec<String> {
        before
            .iter()
            .map(|l| {
                let swap =
                    |name: &str, typ: u32, len: u32, hash: u64, prev: &str| v(&tasks, name, typ, len, hash, prev);
                if l.starts_with(&format!("V\t{}\tSD\t", esc(&tree))) {
                    v(&tree, "SD", 3, 152, 90, "")
                } else if l.starts_with(&format!("V\t{}\tIndex\t", esc(&tree))) {
                    v(&tree, "Index", 4, 4, index, "3")
                } else if l.starts_with(&format!("V\t{}\tHash\t", esc(&tasks))) {
                    swap("Hash", 3, 32, 91, "")
                } else if l.starts_with(&format!("V\t{}\tTriggers\t", esc(&tasks))) {
                    swap("Triggers", 3, triggers_len, 92, "")
                } else if l.starts_with(&format!("V\t{}\tDynamicInfo\t", esc(&tasks))) {
                    swap("DynamicInfo", 3, 36, 93, "")
                } else {
                    l.clone()
                }
            })
            .collect()
    };
    let (_, err, rep) = execdiff(&dir, "listed", &before, &rereg(72, 8), &ops);
    assert_eq!(rep["counts"]["collateral"], 0, "{err}\n{rep:#}");
    assert_eq!(rep["counts"]["authorised"]["task-reregistered"], 4, "{rep:#}");
    // Triggers with another length, or Index (not listed) changed: collateral.
    let (_, _, rep) = execdiff(&dir, "triggers", &before, &rereg(80, 8), &ops);
    assert_eq!(rep["counts"]["collateral"], 1, "{rep:#}");
    let (_, _, rep) = execdiff(&dir, "index", &before, &rereg(72, 77), &ops);
    assert_eq!(rep["counts"]["collateral"], 1, "{rep:#}");
}

/// R2a S12: after a re-registration (a new TaskCache Id) the task file differs; it is excused exactly, and only
/// while it stays a plain file with the same attributes and the Id shows that a registration happened.
#[test]
fn execdiff_task_file_excused_only_after_a_reregistration() {
    const NEW_ID: &str = "{99999999-2222-4333-8444-555555555555}";
    let dir = Dir::new("execdiff-taskfile");
    let before = exec_before();
    let tree = format!("{TC}\\Tree\\PurgeTrap\\Update");
    let file = format!("{TASKS}\\PurgeTrap\\Update");
    let ops =
        [(1, "DeleteTask", "\\PurgeTrap\\Update", json!({"kind": "Skipped", "reason": {"kind": "ChangedSinceScan"}}))];
    // `new_id`: the Id the task has after; `file_line`: the task file after.
    let after = |new_id: &str, file_line: String| -> Vec<String> {
        before
            .iter()
            .map(|l| {
                if l.starts_with(&format!("V\t{}\tId\t", esc(&tree))) {
                    v(&tree, "Id", 1, 78, 70, new_id)
                } else if l.starts_with(&format!("F\t{}\t", esc(&file))) {
                    file_line.clone()
                } else {
                    l.replace(TASK_ID, new_id)
                }
            })
            .collect()
    };
    let changed_file = f(&file, 3010, 99);
    // A new Id: the TaskCache entries moved and the file was written again: no collateral.
    let (_, err, rep) = execdiff(&dir, "moved", &before, &after(NEW_ID, changed_file.clone()), &ops);
    assert_eq!(rep["counts"]["collateral"], 0, "{err}\n{rep:#}");
    assert!(rep["counts"]["authorised"]["task-reregistered"].as_u64().unwrap() >= 1, "{rep:#}");
    // The same Id: no registration is shown, the file change is collateral.
    let (_, _, rep) = execdiff(&dir, "same-id", &before, &after(TASK_ID, changed_file), &ops);
    assert_eq!(rep["counts"]["collateral"], 1, "{rep:#}");
    assert!(rep["collateral"].to_string().contains("Update"), "{rep:#}");
    // A new Id, but the file's attributes changed: collateral.
    let attrs = format!("F\t{}\t3010\t21\t99\t0\n", esc(&file));
    let (_, _, rep) = execdiff(&dir, "attrs", &before, &after(NEW_ID, attrs), &ops);
    assert_eq!(rep["counts"]["collateral"], 1, "{rep:#}");
    // A new Id, but the file became a reparse point: collateral.
    let reparse = format!("F\t{}\t3010\t20\t99\ta0000003\n", esc(&file));
    let (_, _, rep) = execdiff(&dir, "reparse", &before, &after(NEW_ID, reparse), &ops);
    assert_eq!(rep["counts"]["collateral"], 1, "{rep:#}");
}

// ---------------------------------------------------------------------------------------------
// journal: M1b records
// ---------------------------------------------------------------------------------------------

#[test]
fn journal_m1b_variants_read() {
    let dir = Dir::new("journal");
    let conflicts: Vec<Value> = ["ObjectExists", "PendingDelete", "ProgramOutsideRoot", "PasswordNeeded"]
        .iter()
        .enumerate()
        .map(|(i, k)| json!({"rec": "undo_conflict", "op": (i % 3) + 1, "conflict": {"kind": k}}))
        .collect();
    let ops = [
        (1, "DeleteService", "PurgeTrapSvc", json!({"kind": "PendingDelete"})),
        (2, "DeleteTask", "\\PurgeTrap\\Update", json!({"kind": "Done"})),
        (3, "DeleteFirewallRule", RULE, json!({"kind": "Done"})),
    ];
    let (j, _) = journal_and_report(&ops, &conflicts);
    let empty = deep(vec![], vec![], vec![]);
    // Empty captures: the rows fail as "nothing compared", but the journal is read and the report written.
    let (_, err, rep) = fidelity(&dir, "ok", &empty, &empty, &j);
    assert!(rep.is_object() && !err.contains("journal line"), "{err}");
    let got: Vec<(String, String)> = rep["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| (o["action"].as_str().unwrap().to_string(), o["outcome"].as_str().unwrap_or("").to_string()))
        .collect();
    assert_eq!(
        got,
        [
            ("DeleteService".to_string(), "PendingDelete".to_string()),
            ("DeleteTask".to_string(), "Done".to_string()),
            ("DeleteFirewallRule".to_string(), "Done".to_string()),
        ],
        "{rep:#}"
    );
    // An object op whose facts name another object kind is refused.
    let mut bad = format!("{}\n", header(1));
    for r in obj_op(1, "DeleteTask", "\\PurgeTrap\\Update", json!({"kind": "Done"}), Some("service")) {
        bad.push_str(&format!("{r}\n"));
    }
    let (code, err, _) = fidelity(&dir, "bad", &empty, &empty, &bad);
    assert_ne!(code, 0);
    assert!(err.contains("not a task object"), "{err}");
}
