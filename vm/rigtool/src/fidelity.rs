//! `rigtool fidelity`: compares two deep snapshots (before execute, after undo) over the ENGINE_PLAN.md §10.3
//! fields and reports, per executor action type, how many objects came back identical.
//!
//! Compared: every field `deep` records, except the §10.3 exclusions: registry LastWriteTime, file and
//! directory LastWriteTime (parent directories change when a child moves), 8.3 names, and the ambient set.
//! FileId and volume serial are compared only for objects that the journal says were renamed (a quarantine move
//! of the object or of a directory above it); a directory recreated by undo has a new FileId by design.
//!
//! Attribution: each object goes to the journal op that covers it (exact value ops first, then ops that ran
//! (outcome Done or unknown) before absorbed or skipped ones, then the deepest target). Objects no op covers form
//! the "outside plan" row: parents and siblings, which must not change either.
//!
//! The journal is read loosely (rigtool does not link purge-model): every JSON line is a record whose kind is the
//! `record` / `kind` / `rec` / `t` / `type` string field, or the single key of an externally tagged object. From
//! `Intent` records it takes the op id (`op_id`, else a scalar `op` / `id` / `seq`), the op kind (an ExecOp name
//! found in `op`, `kind`, `op_kind` or `exec_op`, else anywhere in the record), the first purge-model Target object
//! in the record (`target` first), `is_dir`, and `renamed`. `Done` records give the outcome per op id. One torn
//! final line is tolerated.

use crate::ambient::AmbientSet;
use crate::canon;
use crate::deep::{self, DeepDoc, FileRec, KeyRec, ValueRec};
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::target::Target;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

pub const SCHEMA: &str = "purge.rig.fidelity/1";

/// ExecOp names (purge-model `op.rs`).
pub const OP_KINDS: &[&str] = &[
    "QuarantineMove",
    "RemoveDirIfEmpty",
    "DeleteKeyTree",
    "DeleteKeyIfEmpty",
    "DeleteValue",
    "EditSegment",
    "RemovePackage",
    "DeleteService",
    "DeleteTask",
    "DeleteFirewallRule",
];
const PLAN_ACTIONS: &[&str] = &["Quarantine", "DeleteKey", "DeleteValue", "EditSegment", "RemoveDirIfEmpty"];
const OUTCOMES: &[&str] = &["Done", "Vanished", "Skipped", "HeldRetry", "PendingReboot", "Failed"];
const TARGET_TYPES: &[&str] = &[
    "Path",
    "RegKey",
    "RegValue",
    "RegValueChanged",
    "RegMultiSzSegment",
    "Service",
    "Task",
    "FirewallRule",
    "AppxPackage",
];

/// Row labels, in report order.
pub const ROWS: &[&str] = &[
    "QuarantineMove file",
    "QuarantineMove dir",
    "RemoveDirIfEmpty",
    "DeleteKeyTree",
    "DeleteKeyIfEmpty",
    "DeleteValue",
    "EditSegment",
    "DeleteService",
    "DeleteTask",
    "DeleteFirewallRule",
    "RemovePackage",
    OUTSIDE,
];
pub const OUTSIDE: &str = "outside plan";

/// Fields never compared (documented in the report).
pub const EXCLUDED: &[&str] = &[
    "file.last_write (incl. parent directories)",
    "file.short_name (8.3)",
    "file.file_id, file.volume_serial unless renamed by a journal op",
    "key.last_write",
    "objects in the ambient set",
];
const FILE_META: &[&str] = &["path", "typed", "last_write", "short_name"];
const FILE_ID_FIELDS: &[&str] = &["file_id", "volume_serial"];
const KEY_META: &[&str] = &["key", "typed", "last_write", "values", "only_values", "omitted"];
const VALUE_META: &[&str] = &["name"];

pub struct FidelityArgs {
    pub before: PathBuf,
    pub after: PathBuf,
    pub journal: PathBuf,
    pub ambient: Option<PathBuf>,
    pub sid: Option<String>,
    pub out: PathBuf,
}

// ---------------------------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct JOp {
    pub id: String,
    pub kind: Option<String>,
    pub target: Option<Target>,
    pub renamed: bool,
    pub is_dir: Option<bool>,
    pub outcome: Option<String>,
    pub line: usize,
}

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

fn pick<'a>(names: &[&'a str], s: &str) -> Option<&'a str> {
    let n = norm(s);
    names.iter().copied().find(|x| norm(x) == n)
}

/// First string value or object key (document order, depth-limited) equal to one of `names`.
fn find_name<'a>(v: &Value, names: &[&'a str], skip: Option<&str>, depth: u32) -> Option<&'a str> {
    if depth > 6 {
        return None;
    }
    match v {
        Value::String(s) => pick(names, s),
        Value::Object(m) => {
            for (k, x) in m {
                if skip == Some(k.as_str()) {
                    continue;
                }
                if let Some(n) = pick(names, k) {
                    return Some(n);
                }
                if let Some(n) = find_name(x, names, None, depth + 1) {
                    return Some(n);
                }
            }
            None
        }
        Value::Array(a) => a.iter().find_map(|x| find_name(x, names, None, depth + 1)),
        _ => None,
    }
}

fn find_target(v: &Value, depth: u32) -> Option<Target> {
    if depth > 6 {
        return None;
    }
    match v {
        Value::Object(m) => {
            if m.get("type").and_then(Value::as_str).is_some_and(|t| TARGET_TYPES.contains(&t))
                && let Ok(t) = serde_json::from_value::<Target>(v.clone())
            {
                return Some(t);
            }
            if let Some(t) = m.get("target").and_then(|x| find_target(x, depth + 1)) {
                return Some(t);
            }
            m.values().find_map(|x| find_target(x, depth + 1))
        }
        Value::Array(a) => a.iter().find_map(|x| find_target(x, depth + 1)),
        _ => None,
    }
}

fn find_bool(v: &Value, key: &str, depth: u32) -> Option<bool> {
    if depth > 6 {
        return None;
    }
    match v {
        Value::Object(m) => {
            if let Some(b) = m.get(key).and_then(Value::as_bool) {
                return Some(b);
            }
            m.values().find_map(|x| find_bool(x, key, depth + 1))
        }
        Value::Array(a) => a.iter().find_map(|x| find_bool(x, key, depth + 1)),
        _ => None,
    }
}

fn scalar(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn op_id(body: &Value) -> Option<String> {
    for k in ["op_id", "op", "id", "seq"] {
        if let Some(s) = scalar(body.get(k)) {
            return Some(s);
        }
    }
    body.get("op").and_then(|o| scalar(o.get("id")).or_else(|| scalar(o.get("op_id"))))
}

/// (kind, body, field that held the kind).
fn record_kind(v: &Value) -> Option<(String, &Value, Option<&'static str>)> {
    let m = v.as_object()?;
    for f in ["record", "kind", "rec", "t", "type"] {
        if let Some(s) = m.get(f).and_then(Value::as_str) {
            return Some((norm(s), v, Some(f)));
        }
    }
    if m.len() == 1 {
        let (k, x) = m.iter().next()?;
        if x.is_object() {
            return Some((norm(k), x, None));
        }
    }
    None
}

/// ExecOp kind for a target and an op or plan action name (the legal pairs of purge-model `resolve`).
fn resolve_kind(t: Option<&Target>, kind: Option<&str>) -> Option<String> {
    let k = match (t, kind) {
        (Some(Target::Service { .. }), _) => "DeleteService",
        (Some(Target::Task { .. }), _) => "DeleteTask",
        (Some(Target::FirewallRule { .. }), _) => "DeleteFirewallRule",
        (Some(Target::AppxPackage { .. }), _) => "RemovePackage",
        (Some(Target::RegKey { .. }), Some("RemoveDirIfEmpty" | "DeleteKeyIfEmpty")) => "DeleteKeyIfEmpty",
        (Some(Target::RegKey { .. }), Some("DeleteKey" | "DeleteKeyTree" | "Quarantine")) => "DeleteKeyTree",
        (Some(Target::Path { .. }), Some("Quarantine" | "QuarantineMove")) => "QuarantineMove",
        (_, Some(k)) => return Some(k.to_string()),
        (_, None) => return None,
    };
    Some(k.to_string())
}

/// Ops of a journal (see the module comment), plus warnings.
pub fn parse_journal(text: &str) -> Result<(Vec<JOp>, Vec<String>)> {
    let mut ops: Vec<JOp> = Vec::new();
    let mut idx: HashMap<String, usize> = HashMap::new();
    let mut warnings = Vec::new();
    let lines: Vec<(usize, &str)> =
        text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())).filter(|(_, l)| !l.is_empty()).collect();
    let n = lines.len();
    for (pos, (ln, l)) in lines.into_iter().enumerate() {
        let v: Value = match serde_json::from_str(l) {
            Ok(v) => v,
            Err(e) if pos + 1 == n => {
                warnings.push(format!("journal line {ln}: torn final record ignored ({e})"));
                continue;
            }
            Err(e) => bail!("journal line {ln}: {e}"),
        };
        let Some((kind, body, kf)) = record_kind(&v) else {
            warnings.push(format!("journal line {ln}: record kind not found"));
            continue;
        };
        match kind.as_str() {
            "header" => {
                if let Some(s) = body.get("schema").and_then(Value::as_str)
                    && !s.starts_with("purge.journal/")
                {
                    warnings.push(format!("journal header schema {s:?} is not purge.journal/*"));
                }
            }
            "intent" => {
                let id = op_id(body).unwrap_or_else(|| format!("line:{ln}"));
                if idx.contains_key(&id) {
                    continue;
                }
                let target = find_target(body, 0);
                let mut kind = None;
                for f in ["op", "kind", "op_kind", "exec_op"] {
                    if Some(f) == kf {
                        continue;
                    }
                    if let Some(x) = body.get(f)
                        && let Some(k) = find_name(x, OP_KINDS, None, 0)
                    {
                        kind = Some(k);
                        break;
                    }
                }
                let kind =
                    kind.or_else(|| find_name(body, OP_KINDS, kf, 0)).or_else(|| find_name(body, PLAN_ACTIONS, kf, 0));
                let kind = resolve_kind(target.as_ref(), kind);
                if target.is_none() {
                    warnings
                        .push(format!("journal line {ln}: op {id} has no target; its objects count as outside plan"));
                }
                let renamed = kind.as_deref() == Some("QuarantineMove") || find_bool(body, "renamed", 0) == Some(true);
                idx.insert(id.clone(), ops.len());
                ops.push(JOp {
                    id,
                    kind,
                    target,
                    renamed,
                    is_dir: find_bool(body, "is_dir", 0),
                    outcome: None,
                    line: ln,
                });
            }
            "done" => {
                let Some(id) = op_id(body) else {
                    warnings.push(format!("journal line {ln}: done record without op id"));
                    continue;
                };
                let outcome = body
                    .get("outcome")
                    .and_then(|o| find_name(o, OUTCOMES, None, 0))
                    .or_else(|| find_name(body, OUTCOMES, kf, 0));
                match idx.get(&id) {
                    Some(&i) => ops[i].outcome = outcome.map(str::to_string),
                    None => warnings.push(format!("journal line {ln}: done for unknown op {id}")),
                }
            }
            _ => {}
        }
    }
    if ops.is_empty() {
        warnings.push("journal: no intent records".into());
    }
    Ok((ops, warnings))
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FieldDiff {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Difference {
    /// `P:<path>`, `K:<key>` or `V:<key>|<name>`.
    pub object: String,
    pub action: String,
    pub op: Option<String>,
    pub fields: Vec<FieldDiff>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Row {
    pub action: String,
    pub ops: u64,
    pub objects: u64,
    pub identical: u64,
    pub differing: u64,
    /// identical / objects, in percent; `null` when nothing was compared.
    pub percent: Option<f64>,
    /// `null` = not compared (RemovePackage: Inverse None).
    pub pass: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OpRow {
    pub id: String,
    pub action: String,
    pub target: Option<String>,
    pub outcome: Option<String>,
    pub renamed: bool,
    pub objects: u64,
    pub differing: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Excluded {
    pub fields: Vec<String>,
    pub ambient_objects: u64,
    /// Present file objects compared without FileId / volume serial (no rename covers them).
    pub file_id_not_required: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FidelityReport {
    pub schema: String,
    pub before: String,
    pub after: String,
    pub journal: String,
    pub ambient: Option<String>,
    pub ok: bool,
    pub rows: Vec<Row>,
    pub differences: Vec<Difference>,
    pub ops: Vec<OpRow>,
    pub excluded: Excluded,
    pub warnings: Vec<String>,
}

impl FidelityReport {
    pub fn failing_rows(&self) -> usize {
        self.rows.iter().filter(|r| r.pass == Some(false)).count()
    }
}

// ---------------------------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------------------------

/// An op prepared for attribution.
struct Prep {
    id: String,
    label: String,
    kind: String,
    /// Primitive targets (canonical).
    prims: Vec<Target>,
    renamed: bool,
    ran: bool,
}

enum Obj<'a> {
    File(&'a str),
    Key(&'a str),
    Value(&'a str, &'a str),
}

impl Prep {
    /// Some((exact value op, target depth)) when this op covers the object.
    fn covers(&self, o: &Obj) -> Option<(bool, usize)> {
        let depth = |p: &str| p.split('\\').count();
        let k = self.kind.as_str();
        for t in &self.prims {
            match (o, t) {
                (Obj::File(p), Target::Path { path }) => {
                    let hit = match k {
                        "RemoveDirIfEmpty" => canon::ci_eq(p, path),
                        _ => canon::is_under_or_eq(p, path),
                    };
                    if hit {
                        return Some((false, depth(path)));
                    }
                }
                (Obj::Key(key) | Obj::Value(key, _), Target::RegKey { path }) => {
                    let hit = match k {
                        "DeleteKeyIfEmpty" => canon::ci_eq(key, path),
                        _ => canon::is_under_or_eq(key, path),
                    };
                    if hit {
                        return Some((false, depth(path)));
                    }
                }
                (
                    Obj::Value(key, name),
                    Target::RegValue { path, name: tn }
                    | Target::RegValueChanged { path, name: tn, .. }
                    | Target::RegMultiSzSegment { path, name: tn, .. },
                ) if canon::ci_eq(key, path) && name.eq_ignore_ascii_case(tn) => {
                    return Some((true, depth(path) + 1));
                }
                _ => {}
            }
        }
        None
    }
}

fn attribute<'p>(preps: &'p [Prep], o: &Obj) -> Option<&'p Prep> {
    preps
        .iter()
        .filter_map(|p| p.covers(o).map(|(exact, d)| (p, exact, d)))
        .max_by_key(|(p, exact, d)| (*exact, p.ran, *d))
        .map(|(p, _, _)| p)
}

fn absent() -> Value {
    json!({ "present": false })
}

/// Differing fields between two records (`None` = no record), skipping `skip`. A record with an `error` on either
/// side is never identical (its fields could not all be read).
fn diff_fields(a: Option<Value>, b: Option<Value>, skip: &[&str]) -> Vec<FieldDiff> {
    let (a, b) = (a.unwrap_or_else(absent), b.unwrap_or_else(absent));
    let pa = a.get("present").and_then(Value::as_bool).unwrap_or(true);
    let pb = b.get("present").and_then(Value::as_bool).unwrap_or(true);
    if pa != pb {
        return vec![FieldDiff { field: "present".into(), before: json!(pa), after: json!(pb) }];
    }
    let (Some(ma), Some(mb)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    let mut names: Vec<&String> = ma.keys().chain(mb.keys()).collect();
    names.sort();
    names.dedup();
    let mut out = Vec::new();
    for n in names {
        if skip.contains(&n.as_str()) {
            continue;
        }
        let va = ma.get(n).cloned().unwrap_or(Value::Null);
        let vb = mb.get(n).cloned().unwrap_or(Value::Null);
        if va != vb || (n == "error" && !va.is_null()) {
            out.push(FieldDiff { field: n.clone(), before: va, after: vb });
        }
    }
    out
}

fn to_value<T: Serialize>(x: Option<&T>) -> Option<Value> {
    x.map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
}

/// Compares two deep snapshots against the journal's ops.
pub fn compare(a: &DeepDoc, c: &DeepDoc, ops: &[JOp], amb: Option<&AmbientSet>, sid: Option<&str>) -> FidelityReport {
    let mut warnings = Vec::new();
    if a.scope.paths != c.scope.paths || a.scope.keys != c.scope.keys || a.scope.values != c.scope.values {
        warnings.push("before and after were captured with different scopes".to_string());
    }
    let fa: HashMap<String, &FileRec> = a.files.iter().map(|r| (canon::fold(&r.path), r)).collect();
    let fc: HashMap<String, &FileRec> = c.files.iter().map(|r| (canon::fold(&r.path), r)).collect();
    let ka: HashMap<String, &KeyRec> = a.keys.iter().map(|r| (canon::fold(&r.key), r)).collect();
    let kc: HashMap<String, &KeyRec> = c.keys.iter().map(|r| (canon::fold(&r.key), r)).collect();

    // Ops -> attribution entries.
    let mut preps: Vec<Prep> = Vec::new();
    let mut op_rows: Vec<OpRow> = Vec::new();
    for o in ops {
        let t = o.target.as_ref().map(|t| t.canonical(sid));
        let kind = o.kind.clone().unwrap_or_else(|| "unknown".into());
        let label = if kind == "QuarantineMove" {
            let dir = t
                .as_ref()
                .and_then(|t| fa.get(&canon::fold(t.path())))
                .and_then(|r| r.is_dir)
                .or(o.is_dir)
                .unwrap_or(false);
            if dir { "QuarantineMove dir" } else { "QuarantineMove file" }.to_string()
        } else {
            kind.clone()
        };
        if o.kind.is_none() {
            warnings.push(format!("op {} (journal line {}): op kind not found", o.id, o.line));
        }
        op_rows.push(OpRow {
            id: o.id.clone(),
            action: label.clone(),
            target: t.as_ref().map(Target::canon_string),
            outcome: o.outcome.clone(),
            renamed: o.renamed,
            objects: 0,
            differing: 0,
        });
        if let Some(t) = t {
            let ran = !matches!(o.outcome.as_deref(), Some("Vanished" | "Skipped" | "Failed"));
            preps.push(Prep { id: o.id.clone(), label, kind, prims: t.primitives(), renamed: o.renamed, ran });
        }
    }
    let op_pos: HashMap<String, usize> = op_rows.iter().enumerate().map(|(i, r)| (r.id.clone(), i)).collect();

    let mut tally: BTreeMap<String, u64> = BTreeMap::new(); // label -> ops
    for r in &op_rows {
        *tally.entry(r.action.clone()).or_default() += 1;
    }
    let mut objects: BTreeMap<String, (u64, u64)> = BTreeMap::new(); // label -> (objects, differing)
    let mut differences = Vec::new();
    let mut excluded = Excluded {
        fields: EXCLUDED.iter().map(|s| s.to_string()).collect(),
        ambient_objects: 0,
        file_id_not_required: 0,
    };

    let is_ambient = |t: Target| amb.and_then(|m| m.union.matches(&t)).is_some();
    let mut record = |cs: String, o: Obj, fields: Box<dyn Fn(bool) -> Vec<FieldDiff> + '_>, excluded: &mut Excluded| {
        let p = attribute(&preps, &o);
        let label = p.map_or(OUTSIDE.to_string(), |p| p.label.clone());
        let renamed = p.is_some_and(|p| p.renamed);
        let e = objects.entry(label.clone()).or_default();
        e.0 += 1;
        if let Some(p) = p
            && let Some(&i) = op_pos.get(&p.id)
        {
            op_rows[i].objects += 1;
        }
        if p.is_some_and(|p| p.kind == "RemovePackage") {
            return;
        }
        if matches!(o, Obj::File(_)) && !renamed {
            excluded.file_id_not_required += 1;
        }
        let f = fields(renamed);
        if f.is_empty() {
            return;
        }
        e.1 += 1;
        if let Some(p) = p
            && let Some(&i) = op_pos.get(&p.id)
        {
            op_rows[i].differing += 1;
        }
        differences.push(Difference { object: cs, action: label, op: p.map(|p| p.id.clone()), fields: f });
    };

    // Files.
    let mut fkeys: Vec<&String> = fa.keys().chain(fc.keys()).collect();
    fkeys.sort();
    fkeys.dedup();
    for f in fkeys {
        let (ra, rc) = (fa.get(f).copied(), fc.get(f).copied());
        let path = ra.or(rc).map(|r| r.path.as_str()).unwrap_or_default();
        if is_ambient(Target::Path { path: path.to_string() }) {
            excluded.ambient_objects += 1;
            continue;
        }
        let fields = Box::new(move |renamed: bool| {
            let mut skip: Vec<&str> = FILE_META.to_vec();
            if !renamed {
                skip.extend_from_slice(FILE_ID_FIELDS);
            }
            diff_fields(to_value(ra), to_value(rc), &skip)
        });
        record(format!("P:{path}"), Obj::File(path), fields, &mut excluded);
    }

    // Keys and their values.
    let mut kkeys: Vec<&String> = ka.keys().chain(kc.keys()).collect();
    kkeys.sort();
    kkeys.dedup();
    for k in kkeys {
        let (ra, rc) = (ka.get(k).copied(), kc.get(k).copied());
        let key = ra.or(rc).map(|r| r.key.as_str()).unwrap_or_default();
        if is_ambient(Target::RegKey { path: key.to_string() }) {
            excluded.ambient_objects += 1;
        } else {
            let fields = Box::new(move |_: bool| diff_fields(to_value(ra), to_value(rc), KEY_META));
            record(format!("K:{key}"), Obj::Key(key), fields, &mut excluded);
        }
        let vals = |r: Option<&'_ KeyRec>| -> BTreeMap<String, ValueRec> {
            r.map(|r| r.values.iter().map(|v| (v.name.to_lowercase(), v.clone())).collect()).unwrap_or_default()
        };
        let (va, vc) = (vals(ra), vals(rc));
        let mut names: Vec<&String> = va.keys().chain(vc.keys()).collect();
        names.sort();
        names.dedup();
        for n in names {
            let (xa, xc) = (va.get(n), vc.get(n));
            let name = xa.or(xc).map(|v| v.name.as_str()).unwrap_or_default();
            if is_ambient(Target::RegValue { path: key.to_string(), name: name.to_string() }) {
                excluded.ambient_objects += 1;
                continue;
            }
            let (ja, jc) = (to_value(xa), to_value(xc));
            let fields = Box::new(move |_: bool| diff_fields(ja.clone(), jc.clone(), VALUE_META));
            record(format!("V:{key}|{name}"), Obj::Value(key, name), fields, &mut excluded);
        }
    }

    // Rows.
    let mut out_rows = Vec::new();
    let mut labels: Vec<String> = ROWS.iter().map(|s| s.to_string()).collect();
    for l in tally.keys().chain(objects.keys()) {
        if !labels.contains(l) {
            labels.push(l.clone());
        }
    }
    for l in labels {
        let n_ops = tally.get(&l).copied().unwrap_or(0);
        let (n_obj, n_diff) = objects.get(&l).copied().unwrap_or((0, 0));
        if n_ops == 0 && n_obj == 0 && l != OUTSIDE {
            continue;
        }
        let mut r = Row {
            action: l.clone(),
            ops: n_ops,
            objects: n_obj,
            identical: 0,
            differing: 0,
            percent: None,
            pass: None,
            note: None,
        };
        if l == "RemovePackage" {
            r.note = Some("Inverse None: not compared".into());
        } else {
            r.identical = n_obj - n_diff;
            r.differing = n_diff;
            if n_obj > 0 {
                r.percent = Some(((r.identical as f64) * 10000.0 / n_obj as f64).round() / 100.0);
                r.pass = Some(n_diff == 0);
            } else if l == OUTSIDE {
                r.pass = Some(true);
            } else {
                r.pass = Some(false);
                r.note = Some("no deep object in scope for these ops (scope incomplete?)".into());
            }
        }
        out_rows.push(r);
    }
    let ok = !out_rows.iter().any(|r| r.pass == Some(false));
    FidelityReport {
        schema: SCHEMA.to_string(),
        before: String::new(),
        after: String::new(),
        journal: String::new(),
        ambient: None,
        ok,
        rows: out_rows,
        differences,
        ops: op_rows,
        excluded,
        warnings,
    }
}

fn read_deep(p: &Path) -> Result<DeepDoc> {
    let d: DeepDoc = jsonio::read(p)?;
    if d.schema != deep::SCHEMA {
        bail!("{}: schema {:?}, want {}", p.display(), d.schema, deep::SCHEMA);
    }
    Ok(d)
}

pub fn cmd_fidelity(a: &FidelityArgs) -> Result<FidelityReport> {
    let before = read_deep(&a.before)?;
    let after = read_deep(&a.after)?;
    let text = jsonio::read_text(&a.journal)?;
    let (ops, jw) = parse_journal(&text).with_context(|| format!("journal {}", a.journal.display()))?;
    let amb = match &a.ambient {
        Some(p) => Some(AmbientSet::load(p)?),
        None => None,
    };
    let sid = a.sid.clone().or_else(|| before.sid.clone());
    let mut rep = compare(&before, &after, &ops, amb.as_ref(), sid.as_deref());
    rep.before = a.before.display().to_string();
    rep.after = a.after.display().to_string();
    rep.journal = a.journal.display().to_string();
    rep.ambient = a.ambient.as_ref().map(|p| p.display().to_string());
    let mut w = jw;
    w.append(&mut rep.warnings);
    rep.warnings = w;
    jsonio::write(&a.out, &rep)?;
    for r in &rep.rows {
        eprintln!(
            "fidelity: {:<20} ops {:>4}  objects {:>6}  differing {:>4}  {}",
            r.action,
            r.ops,
            r.objects,
            r.differing,
            match (r.pass, r.percent) {
                (None, _) => "not compared".to_string(),
                (Some(p), Some(pc)) => format!("{pc:.2} % {}", if p { "pass" } else { "FAIL" }),
                (Some(p), None) => (if p { "pass" } else { "FAIL (nothing compared)" }).to_string(),
            }
        );
    }
    for w in &rep.warnings {
        eprintln!("fidelity: warning: {w}");
    }
    eprintln!("fidelity: {} -> {}", if rep.ok { "ok" } else { "FAILED" }, a.out.display());
    Ok(rep)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::{StreamRec, sha256_hex};

    const R: &str = "C:\\Program Files\\Fx";
    const K: &str = "HKLM\\SOFTWARE\\Fx";

    fn file(path: &str, content: &str, n: u64) -> FileRec {
        FileRec {
            path: path.into(),
            present: true,
            is_dir: Some(false),
            attributes: Some("0x00000020".into()),
            size: Some(content.len() as u64),
            sha256: Some(sha256_hex(content.as_bytes())),
            streams: Some(Vec::new()),
            links: Some(1),
            file_id: Some(format!("{n:016x}")),
            volume_serial: Some(0x1234),
            owner: Some("BA".into()),
            sddl: Some("O:BAG:SYD:AI(A;ID;FA;;;BA)".into()),
            short_name: None,
            last_write: Some(100 + n),
            ..Default::default()
        }
    }

    fn dir(path: &str, n: u64) -> FileRec {
        FileRec {
            is_dir: Some(true),
            attributes: Some("0x00000010".into()),
            size: None,
            sha256: None,
            ..file(path, "", n)
        }
    }

    fn val(name: &str, typ: u32, data: &str) -> ValueRec {
        ValueRec { name: name.into(), name_hex: None, typ, len: data.len() as u32, sha256: sha256_hex(data.as_bytes()) }
    }

    fn key(k: &str, class: &str, values: Vec<ValueRec>) -> KeyRec {
        KeyRec {
            key: k.into(),
            present: true,
            class: Some(class.into()),
            owner: Some("BA".into()),
            sddl: Some("O:BAG:SYD:PAI(A;CI;KA;;;BA)".into()),
            is_link: Some(false),
            last_write: Some(5),
            values,
            ..Default::default()
        }
    }

    fn doc() -> DeepDoc {
        let mut ads = file(&format!("{R}\\ads\\ads.bin"), "ads", 1);
        ads.streams = Some(vec![StreamRec { name: ":meta:$DATA".into(), size: 3, sha256: Some(sha256_hex(b"abc")) }]);
        let mut hl = file(&format!("{R}\\hl\\a.dll"), "hl", 2);
        hl.links = Some(2);
        let mut hl2 = file(&format!("{R}\\hl\\copy\\a-link.dll"), "hl", 2);
        hl2.links = Some(2);
        DeepDoc {
            schema: deep::SCHEMA.into(),
            files: vec![
                dir(R, 10),
                dir(&format!("{R}\\ads"), 11),
                ads,
                dir(&format!("{R}\\hl"), 12),
                hl,
                dir(&format!("{R}\\hl\\copy"), 13),
                hl2,
                file(&format!("{R}\\single.txt"), "single", 3),
                dir(&format!("{R}\\empty-dir"), 14),
                file(&format!("{R}\\sibling.txt"), "not in plan", 4),
            ],
            keys: vec![
                key(K, "", vec![]),
                key(&format!("{K}\\Tree"), "TreeClass", vec![val("", 1, "d"), val("bin", 3, "xyz")]),
                key(&format!("{K}\\Tree\\Sub"), "SubClass", vec![val("v", 4, "1234")]),
                key(&format!("{K}\\Empty"), "", vec![]),
                key(&format!("{K}\\Values"), "", vec![val("keep", 1, "k"), val("del", 2, "x"), val("Path", 2, "a;b")]),
            ],
            ..Default::default()
        }
    }

    fn journal() -> String {
        let lines = [
            json!({"record": "Header", "schema": "purge.journal/1"}),
            json!({"record": "Intent", "op_id": 1, "op": {"QuarantineMove": {"target": {"type": "Path", "path": format!("{R}\\ads\\ads.bin")}}}}),
            json!({"record": "Intent", "op_id": 2, "op": {"kind": "QuarantineMove"}, "target": {"type": "Path", "path": format!("{R}\\hl")}}),
            json!({"record": "Intent", "op_id": 3, "op": "QuarantineMove", "target": {"type": "Path", "path": format!("{R}\\single.txt")}}),
            json!({"record": "Intent", "op_id": 4, "op": "RemoveDirIfEmpty", "target": {"type": "Path", "path": format!("{R}\\empty-dir")}}),
            json!({"record": "Intent", "op_id": 5, "op": "DeleteKeyTree", "target": {"type": "RegKey", "path": format!("{K}\\Tree")}}),
            json!({"record": "Intent", "op_id": 6, "action": "RemoveDirIfEmpty", "target": {"type": "RegKey", "path": format!("{K}\\Empty")}}),
            json!({"record": "Intent", "op_id": 7, "op": "DeleteValue", "target": {"type": "RegValue", "path": format!("{K}\\Values"), "name": "del"}}),
            json!({"Intent": {"op_id": 8, "op": "EditSegment", "target": {"type": "RegMultiSzSegment", "path": format!("{K}\\Values"), "name": "Path", "segment": "b"}}}),
            json!({"record": "Done", "op_id": 1, "outcome": "Done"}),
            json!({"record": "Done", "op_id": 6, "outcome": {"Skipped": {"reason": "NoLongerEmpty"}}}),
        ];
        let mut s: String = lines.iter().map(|l| format!("{l}\n")).collect();
        s.push_str("{\"record\":\"Done\",\"op_");
        s
    }

    fn run(a: &DeepDoc, c: &DeepDoc) -> FidelityReport {
        let (ops, _) = parse_journal(&journal()).unwrap();
        compare(a, c, &ops, None, None)
    }

    fn row<'a>(r: &'a FidelityReport, l: &str) -> &'a Row {
        r.rows.iter().find(|x| x.action == l).unwrap_or_else(|| panic!("row {l}"))
    }

    #[test]
    fn journal_shapes() {
        let (ops, w) = parse_journal(&journal()).unwrap();
        assert_eq!(ops.len(), 8);
        let k: Vec<&str> = ops.iter().map(|o| o.kind.as_deref().unwrap()).collect();
        assert_eq!(
            k,
            [
                "QuarantineMove",
                "QuarantineMove",
                "QuarantineMove",
                "RemoveDirIfEmpty",
                "DeleteKeyTree",
                "DeleteKeyIfEmpty",
                "DeleteValue",
                "EditSegment"
            ]
        );
        assert!(ops[0].renamed && ops[1].renamed && !ops[3].renamed);
        assert_eq!(ops[0].outcome.as_deref(), Some("Done"));
        assert_eq!(ops[5].outcome.as_deref(), Some("Skipped"));
        assert_eq!(ops[7].id, "8");
        assert!(w.iter().any(|x| x.contains("torn")));
        assert!(parse_journal("{bad\n{\"record\":\"Intent\"}\n").is_err());
    }

    #[test]
    fn identical_is_full_fidelity() {
        let r = run(&doc(), &doc());
        assert!(r.ok, "{:#?}", r.differences);
        for l in [
            "QuarantineMove file",
            "QuarantineMove dir",
            "RemoveDirIfEmpty",
            "DeleteKeyTree",
            "DeleteKeyIfEmpty",
            "DeleteValue",
            "EditSegment",
            OUTSIDE,
        ] {
            let x = row(&r, l);
            assert_eq!(x.percent, Some(100.0), "{l}");
            assert_eq!(x.pass, Some(true), "{l}");
            assert!(x.objects > 0, "{l}");
        }
        assert_eq!(row(&r, "QuarantineMove dir").objects, 4);
        assert_eq!(row(&r, "DeleteValue").objects, 1);
        assert_eq!(row(&r, "EditSegment").objects, 1);
        // keep value + Values key + root key + root dir + sibling + ads dir
        assert_eq!(row(&r, OUTSIDE).objects, 6);
    }

    /// Each single-field mutation is detected once, on the expected row and field.
    #[test]
    fn single_field_mutations() {
        type Mut = Box<dyn Fn(&mut DeepDoc)>;
        let fi = |d: &mut DeepDoc, p: &str| -> usize { d.files.iter().position(|f| f.path == p).unwrap() };
        let ki = |d: &mut DeepDoc, k: &str| -> usize { d.keys.iter().position(|x| x.key == k).unwrap() };
        let ads = format!("{R}\\ads\\ads.bin");
        let hl = format!("{R}\\hl\\a.dll");
        let single = format!("{R}\\single.txt");
        let empty = format!("{R}\\empty-dir");
        let tree = format!("{K}\\Tree");
        let sub = format!("{K}\\Tree\\Sub");
        let values = format!("{K}\\Values");
        let cases: Vec<(&str, &str, Mut)> = vec![
            (
                "QuarantineMove file",
                "sha256",
                Box::new({
                    let p = single.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].sha256 = Some(sha256_hex(b"changed byte"))
                    }
                }),
            ),
            (
                "QuarantineMove file",
                "attributes",
                Box::new({
                    let p = single.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].attributes = Some("0x00000021".into())
                    }
                }),
            ),
            (
                "QuarantineMove file",
                "streams",
                Box::new({
                    let p = ads.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].streams = Some(vec![])
                    }
                }),
            ),
            (
                "QuarantineMove file",
                "file_id",
                Box::new({
                    let p = ads.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].file_id = Some("ffff".into())
                    }
                }),
            ),
            (
                "QuarantineMove dir",
                "links",
                Box::new({
                    let p = hl.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].links = Some(1)
                    }
                }),
            ),
            (
                "QuarantineMove dir",
                "file_id",
                Box::new({
                    let p = hl.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].file_id = Some("ffff".into())
                    }
                }),
            ),
            (
                "RemoveDirIfEmpty",
                "attributes",
                Box::new({
                    let p = empty.clone();
                    move |d| {
                        let i = fi(d, &p);
                        d.files[i].attributes = Some("0x00000012".into())
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "sddl",
                Box::new({
                    let k = tree.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].sddl = Some("O:BAG:SYD:PAI(A;CI;KA;;;BA)(A;CI;KR;;;BU)".into())
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "class",
                Box::new({
                    let k = sub.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].class = Some(String::new())
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "type",
                Box::new({
                    let k = tree.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values[1].typ = 0
                    }
                }),
            ),
            (
                "DeleteKeyTree",
                "is_link",
                Box::new({
                    let k = sub.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].is_link = Some(true)
                    }
                }),
            ),
            (
                "DeleteKeyIfEmpty",
                "present",
                Box::new({
                    let k = format!("{K}\\Empty");
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i] = KeyRec { key: d.keys[i].key.clone(), present: false, ..Default::default() }
                    }
                }),
            ),
            (
                "DeleteValue",
                "type",
                Box::new({
                    let k = values.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values[1].typ = 1
                    }
                }),
            ),
            (
                "DeleteValue",
                "present",
                Box::new({
                    let k = values.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values.remove(1);
                    }
                }),
            ),
            (
                "EditSegment",
                "sha256",
                Box::new({
                    let k = values.clone();
                    move |d| {
                        let i = ki(d, &k);
                        d.keys[i].values[2].sha256 = sha256_hex(b"a;b;b")
                    }
                }),
            ),
            (
                OUTSIDE,
                "sha256",
                Box::new(move |d| {
                    let i = fi(d, &format!("{R}\\sibling.txt"));
                    d.files[i].sha256 = Some(sha256_hex(b"collateral"))
                }),
            ),
            (
                OUTSIDE,
                "error",
                Box::new(move |d| {
                    let i = fi(d, R);
                    d.files[i].error = Some("sddl: 5".into())
                }),
            ),
        ];
        for (want_row, want_field, m) in cases {
            let a = doc();
            let mut c = doc();
            m(&mut c);
            let r = run(&a, &c);
            assert!(!r.ok, "{want_row}/{want_field} not detected");
            assert_eq!(r.differences.len(), 1, "{want_row}/{want_field}: {:#?}", r.differences);
            let d = &r.differences[0];
            assert_eq!(d.action, want_row, "{want_field}: {d:#?}");
            assert_eq!(d.fields.len(), 1, "{d:#?}");
            assert_eq!(d.fields[0].field, want_field);
            let x = row(&r, want_row);
            assert_eq!((x.differing, x.pass), (1, Some(false)));
            assert!(x.percent.unwrap() < 100.0);
            for other in r.rows.iter().filter(|x| x.action != want_row) {
                assert_ne!(other.pass, Some(false), "{want_row}/{want_field} also failed {}", other.action);
            }
        }
    }

    #[test]
    fn excluded_fields_never_fail() {
        let a = doc();
        let mut c = doc();
        for f in &mut c.files {
            f.last_write = Some(999_999);
            f.short_name = Some("PROGRA~1".into());
        }
        for k in &mut c.keys {
            k.last_write = Some(999_999);
        }
        // Not renamed: a recreated directory and a parent get new FileIds.
        for p in [format!("{R}\\empty-dir"), R.to_string(), format!("{R}\\sibling.txt")] {
            let i = c.files.iter().position(|f| f.path == p).unwrap();
            c.files[i].file_id = Some("abcdef".into());
            c.files[i].volume_serial = Some(9);
        }
        let r = run(&a, &c);
        assert!(r.ok, "{:#?}", r.differences);
        assert!(r.excluded.file_id_not_required >= 3);
    }

    #[test]
    fn ambient_objects_are_excluded() {
        let a = doc();
        let mut c = doc();
        let i = c.files.iter().position(|f| f.path.ends_with("sibling.txt")).unwrap();
        c.files[i].sha256 = Some("00".into());
        let amb = AmbientSet {
            union: crate::ambient::Matcher::new("u", &[format!("P:{R}\\sibling.txt")], &[]).unwrap(),
            runs: Vec::new(),
        };
        let (ops, _) = parse_journal(&journal()).unwrap();
        let r = compare(&a, &c, &ops, Some(&amb), None);
        assert!(r.ok, "{:#?}", r.differences);
        assert_eq!(r.excluded.ambient_objects, 1);
    }

    #[test]
    fn op_without_objects_fails_its_row() {
        let a = doc();
        let j = format!(
            "{}\n",
            json!({"record": "Intent", "op_id": 1, "op": "DeleteKeyTree", "target": {"type": "RegKey", "path": "HKLM\\SOFTWARE\\NotCaptured"}})
        );
        let (ops, _) = parse_journal(&j).unwrap();
        let r = compare(&a, &a, &ops, None, None);
        assert!(!r.ok);
        let x = row(&r, "DeleteKeyTree");
        assert_eq!((x.objects, x.pass), (0, Some(false)));
        // RemovePackage is reported, never compared.
        let j = format!(
            "{}\n",
            json!({"record": "Intent", "op_id": 1, "target": {"type": "AppxPackage", "full_name": "A_1"}})
        );
        let (ops, _) = parse_journal(&j).unwrap();
        let r = compare(&a, &a, &ops, None, None);
        assert!(r.ok);
        assert_eq!(row(&r, "RemovePackage").pass, None);
    }

    #[test]
    fn nested_ops_attribute_to_the_op_that_ran() {
        let a = doc();
        let mut c = doc();
        let i = c.files.iter().position(|f| f.path.ends_with("a-link.dll")).unwrap();
        c.files[i].file_id = Some("ff".into());
        let j: String = [
            json!({"record": "Intent", "op_id": "child", "op": "QuarantineMove", "target": {"type": "Path", "path": format!("{R}\\hl\\copy")}}),
            json!({"record": "Intent", "op_id": "parent", "op": "QuarantineMove", "target": {"type": "Path", "path": format!("{R}\\hl")}}),
            json!({"record": "Done", "op_id": "child", "outcome": "Vanished"}),
            json!({"record": "Done", "op_id": "parent", "outcome": "Done"}),
        ]
        .iter()
        .map(|l| format!("{l}\n"))
        .collect();
        let (ops, _) = parse_journal(&j).unwrap();
        let r = compare(&a, &c, &ops, None, None);
        assert_eq!(r.differences.len(), 1);
        assert_eq!(r.differences[0].op.as_deref(), Some("parent"));
        assert_eq!(r.differences[0].fields[0].field, "file_id");
    }

    /// Live: deep on a temp tree and a test key, twice; then real mutations (key DACL ACE, file attribute,
    /// ADS removed, value data) are found on the right rows.
    #[cfg(windows)]
    #[test]
    fn live_round_trip() {
        use crate::deep::testenv::{TempDir, TestKey};
        use crate::deep::{Scope, capture};
        let td = TempDir::new();
        let root = td.path();
        std::fs::create_dir_all(format!("{root}\\app\\tree\\sub")).unwrap();
        std::fs::write(format!("{root}\\app\\tree\\sub\\f.txt"), b"tree file").unwrap();
        let single = format!("{root}\\app\\single.bin");
        std::fs::write(&single, b"single").unwrap();
        std::fs::write(format!("{single}:meta"), b"m").unwrap();
        let k = TestKey::new();
        k.create("Tree", Some("Cls"));
        k.create("Tree\\Sub", None);
        k.set("Tree\\Sub", "v", 4, &1u32.to_le_bytes());
        k.create("Vals", None);
        k.set("Vals", "del", 3, &[1, 2, 3]);
        k.set("Vals", "keep", 3, &[4]);

        let mut b = deep::ScopeBuilder::new(None, None);
        let targets = json!({"schema": "purge.rig.targets/0", "targets": [
            {"target": {"type": "Path", "path": format!("{root}\\app\\tree")}},
            {"target": {"type": "Path", "path": single}},
            {"target": {"type": "RegKey", "path": k.canon("Tree")}},
            {"target": {"type": "RegValue", "path": k.canon("Vals"), "name": "del"}}
        ]});
        b.add_doc(&targets).unwrap();
        let scope: Scope = b.finish();
        assert!(scope.warnings.is_empty(), "{:?}", scope.warnings);
        let j: String = [
            json!({"record": "Intent", "op_id": 1, "op": "QuarantineMove", "target": {"type": "Path", "path": format!("{root}\\app\\tree")}}),
            json!({"record": "Intent", "op_id": 2, "op": "QuarantineMove", "target": {"type": "Path", "path": single}}),
            json!({"record": "Intent", "op_id": 3, "op": "DeleteKeyTree", "target": {"type": "RegKey", "path": k.canon("Tree")}}),
            json!({"record": "Intent", "op_id": 4, "op": "DeleteValue", "target": {"type": "RegValue", "path": k.canon("Vals"), "name": "del"}}),
        ]
        .iter()
        .map(|l| format!("{l}\n"))
        .collect();
        let (ops, w) = parse_journal(&j).unwrap();
        assert!(w.is_empty(), "{w:?}");

        let a = capture(&scope, None);
        assert_eq!(a.errors, 0, "{:#?}", a.files.iter().chain([]).filter(|f| f.error.is_some()).collect::<Vec<_>>());
        let c = capture(&scope, None);
        let r = compare(&a, &c, &ops, None, None);
        assert!(r.ok, "{:#?}", r.differences);
        assert_eq!(row(&r, "QuarantineMove dir").percent, Some(100.0));
        assert_eq!(row(&r, "QuarantineMove file").objects, 1);
        assert_eq!(row(&r, "DeleteKeyTree").objects, 3); // Tree, Sub, Sub|v
        assert_eq!(row(&r, "DeleteValue").objects, 1);

        k.set_sddl("Tree\\Sub", "D:PAI(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;OW)(A;CI;KR;;;BU)");
        k.set("Vals", "del", 3, &[1, 2, 4]);
        std::fs::remove_file(format!("{single}:meta")).unwrap();
        let f = format!("{root}\\app\\tree\\sub\\f.txt");
        let mut p = std::fs::metadata(&f).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&f, p.clone()).unwrap();
        let c2 = capture(&scope, None);
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        std::fs::set_permissions(&f, p).unwrap();
        let r = compare(&a, &c2, &ops, None, None);
        assert!(!r.ok);
        let got: Vec<(String, String)> = r
            .differences
            .iter()
            .map(|d| (d.action.clone(), d.fields.iter().map(|f| f.field.clone()).collect::<Vec<_>>().join(",")))
            .collect();
        assert!(got.contains(&("DeleteKeyTree".into(), "sddl".into())), "{got:?}");
        assert!(got.contains(&("DeleteValue".into(), "sha256".into())), "{got:?}");
        assert!(got.contains(&("QuarantineMove file".into(), "streams".into())), "{got:?}");
        assert!(got.contains(&("QuarantineMove dir".into(), "attributes".into())), "{got:?}");
        assert_eq!(r.differences.len(), 4, "{got:?}");
    }
}
