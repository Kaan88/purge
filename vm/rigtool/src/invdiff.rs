//! `rigtool invdiff`: the M1a inventory exit check (ENGINE_PLAN §11.1, §4.1). Compares the engine's
//! inventory (`purge-engine inventory --json`, `purge.inventory/0`) with the rig's raw enumeration
//! (`lists-<run>-<phase>.json`, RIG.md §3) and explains every difference.
//!
//! - **Reference set**: the `uninstall[]` rows of the lists file (riglib `UninstallEntries`: HKLM 64-bit,
//!   `WOW6432Node`, `HKU\<sid>` of the loaded `S-1-5-21-…` hives) keyed by canonical key path, plus the
//!   `msi[]` product codes (riglib `MsiProducts`, a registry enumeration of `Installer\UserData\<SID>\Products`).
//!   The legacy array-shaped `vm\results\lists-registry.json` (rows `{key,name,version,sys,parent,uninstall,
//!   quiet,size,loc}`) is accepted too; it has no MSI list and no product code column, so those are not compared.
//! - **Engine set**: `entries[]` keyed by canonical `key_path`; the MSI code set is `msi_only[]` plus the
//!   `product_code` of every entry Windows Installer knows (`msi` is set: the engine merged it with a product
//!   from `MsiEnumProductsExW`).
//! - Keys on both sides go through [`canon::canon_reg`] (`HKEY_CURRENT_USER` -> `HKU\<sid>` with `--sid`,
//!   else the lists file's `user_sid`).
//! - Differences: `only_in_engine`, `only_in_reference` (keys and MSI codes) and field mismatches on keys
//!   present on both sides (name, version, uninstall string, quiet string, SystemComponent, ParentKeyName,
//!   product code). Strings are compared trimmed, blank = absent (the engine trims and drops blank values);
//!   a missing reference name stands for the key name (the engine's `display_name` fallback). The rig reads
//!   values through .NET `GetValue`, which expands `REG_EXPAND_SZ`, while the engine keeps them as written:
//!   a `%VAR%` in the engine's value matches any text in the reference's (counted as `expanded`).
//! - Every difference is matched against explanation rules `{match, side, field?, why}` (first match
//!   wins); [`Report::exit_code`] is 1 while any difference is unexplained.

use crate::canon::{self, CiStr, CiString};
use crate::err::{Context, Result, bail};
use crate::jsonio;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The `schema` of the JSON report.
pub const SCHEMA: &str = "rigtool.invdiff/0";
/// The inventory schema this command reads.
const INVENTORY_SCHEMA: &str = "purge.inventory/0";

// ---------------------------------------------------------------------------------------------
// Normalised rows (both sides)
// ---------------------------------------------------------------------------------------------

/// One Uninstall key with the compared fields, normalised (trimmed, blank = `None`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Row {
    /// Canonical key path.
    pub key: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub uninstall: Option<String>,
    pub quiet: Option<String>,
    pub sys: bool,
    pub parent: Option<String>,
    /// MSI product code. Outer `None`: the input carries no product code for this row (legacy shape).
    pub code: Option<Option<String>>,
}

/// The shape a lists file was read in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Shape {
    /// `lists-<run>-<phase>.json` (RIG.md §3).
    Lists,
    /// The legacy array `vm\results\lists-registry.json`.
    Legacy,
}

/// The rig's raw enumeration.
#[derive(Debug, Clone)]
pub struct Reference {
    pub shape: Shape,
    pub rows: Vec<Row>,
    /// Upper-case MSI product codes; `None` when the input has no MSI list (legacy shape).
    pub msi: Option<Vec<String>>,
    /// The SID HKCU was mapped to.
    pub sid: Option<String>,
}

/// The engine's inventory, normalised.
#[derive(Debug, Clone, Default)]
pub struct Engine {
    pub rows: Vec<Row>,
    /// Upper-case product codes Windows Installer reported (entries with `msi` set, plus `msi_only`),
    /// with a display name.
    pub msi: Vec<(String, Option<String>)>,
}

fn norm(s: Option<&str>) -> Option<String> {
    s.map(str::trim).filter(|t| !t.is_empty()).map(str::to_string)
}

/// A JSON scalar as text (PowerShell writes a DWORD `DisplayVersion` as a number).
fn scalar(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => norm(Some(s)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `SystemComponent` as riglib writes it: `true`, `1`, `"1"`; anything else is false.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().is_some_and(|i| i != 0),
        Some(Value::String(s)) => s.trim() == "1",
        _ => false,
    }
}

/// PowerShell's `ConvertTo-Json` writes a one-element array as the element itself and an empty one as null.
fn as_list(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        Some(o @ Value::Object(_)) => vec![o.clone()],
        _ => Vec::new(),
    }
}

fn leaf(key: &str) -> &str {
    key.rsplit('\\').next().unwrap_or(key)
}

/// Read a lists file (either shape). `sid` (from `--sid`) wins over the file's `user_sid`.
pub fn parse_reference(v: &Value, sid: Option<&str>) -> Result<Reference> {
    let (shape, rows, msi, file_sid) = match v {
        Value::Array(a) => (Shape::Legacy, a.clone(), None, None),
        Value::Object(o) => {
            if !o.contains_key("uninstall") {
                bail!("lists file has no `uninstall` list");
            }
            let msi = o.contains_key("msi").then(|| as_list(o.get("msi")));
            let file_sid = o.get("user_sid").and_then(Value::as_str).map(str::to_string);
            (Shape::Lists, as_list(o.get("uninstall")), msi, file_sid)
        }
        _ => bail!("lists file is neither an object nor an array"),
    };
    let sid = sid.map(str::to_string).or(file_sid).filter(|s| !s.trim().is_empty());
    let mut out = Vec::with_capacity(rows.len());
    for (i, r) in rows.iter().enumerate() {
        let key = r.get("key").and_then(Value::as_str).with_context(|| format!("uninstall row {i} has no key"))?;
        let key = canon::canon_reg(key, sid.as_deref());
        let name = scalar(r.get("name")).or_else(|| Some(leaf(&key).to_string()));
        out.push(Row {
            name,
            version: scalar(r.get("version")),
            uninstall: scalar(r.get("uninstall")),
            quiet: scalar(r.get("quiet")),
            sys: truthy(r.get("sys")),
            parent: scalar(r.get("parent")),
            code: r.get("msi").map(|m| scalar(Some(m)).map(|c| c.to_ascii_uppercase())),
            key,
        });
    }
    let msi = match msi {
        Some(list) => {
            let mut codes = Vec::new();
            for (i, m) in list.iter().enumerate() {
                match scalar(m.get("code")) {
                    Some(c) => codes.push(c.to_ascii_uppercase()),
                    None => bail!("msi row {i} has no code"),
                }
            }
            Some(codes)
        }
        None => None,
    };
    Ok(Reference { shape, rows: out, msi, sid })
}

// Own serde view of `purge.inventory/0` (rigtool does not depend on the product workspace).

#[derive(Deserialize)]
struct InvDoc {
    schema: String,
    entries: Vec<InvEntry>,
    #[serde(default)]
    msi_only: Vec<InvMsiOnly>,
}

#[derive(Deserialize)]
struct InvEntry {
    key_path: String,
    display_name: String,
    #[serde(default)]
    version: Option<String>,
    flags: InvFlags,
    #[serde(default)]
    product_code: Option<String>,
    #[serde(default)]
    uninstall_string: Option<String>,
    #[serde(default)]
    quiet_uninstall_string: Option<String>,
    #[serde(default)]
    msi: Option<Value>,
}

#[derive(Deserialize)]
struct InvFlags {
    #[serde(default)]
    system_component: bool,
    #[serde(default)]
    parent_key: Option<String>,
}

#[derive(Deserialize)]
struct InvMsiOnly {
    product_code: String,
    #[serde(default)]
    product_name: Option<String>,
}

/// Read an inventory document.
pub fn parse_engine(v: Value, sid: Option<&str>) -> Result<Engine> {
    let doc: InvDoc = serde_json::from_value(v).context("inventory")?;
    if doc.schema != INVENTORY_SCHEMA {
        bail!("inventory schema is {:?}, expected {INVENTORY_SCHEMA:?}", doc.schema);
    }
    let mut e = Engine::default();
    for x in doc.entries {
        let code = norm(x.product_code.as_deref()).map(|c| c.to_ascii_uppercase());
        if x.msi.as_ref().is_some_and(|m| !m.is_null())
            && let Some(c) = &code
        {
            e.msi.push((c.clone(), norm(Some(&x.display_name))));
        }
        e.rows.push(Row {
            key: canon::canon_reg(&x.key_path, sid),
            name: norm(Some(&x.display_name)),
            version: norm(x.version.as_deref()),
            uninstall: norm(x.uninstall_string.as_deref()),
            quiet: norm(x.quiet_uninstall_string.as_deref()),
            sys: x.flags.system_component,
            parent: norm(x.flags.parent_key.as_deref()),
            code: Some(code),
        });
    }
    for m in doc.msi_only {
        e.msi.push((m.product_code.trim().to_ascii_uppercase(), norm(m.product_name.as_deref())));
    }
    Ok(e)
}

// ---------------------------------------------------------------------------------------------
// Explanation rules
// ---------------------------------------------------------------------------------------------

/// Which differences a rule may explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Engine,
    Reference,
    Mismatch,
    Any,
}

#[derive(Deserialize)]
struct RuleIn {
    #[serde(rename = "match")]
    pattern: String,
    #[serde(default)]
    side: Option<String>,
    #[serde(default)]
    field: Option<String>,
    why: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RulesIn {
    List(Vec<RuleIn>),
    Doc { rules: Vec<RuleIn> },
}

/// One explanation rule: a case-insensitive regex on the canonical key or the MSI code.
#[derive(Debug, Clone)]
pub struct Rule {
    pub pattern: String,
    re: Regex,
    pub side: Side,
    /// Only for mismatches of this field (a rule with a field never explains a presence difference).
    pub field: Option<String>,
    pub why: String,
}

/// Parse an explanation file: `{ "rules": [...] }` or a bare array.
pub fn parse_rules(v: Value) -> Result<Vec<Rule>> {
    let list = match serde_json::from_value::<RulesIn>(v).context("explanation rules")? {
        RulesIn::List(l) | RulesIn::Doc { rules: l } => l,
    };
    let mut out = Vec::with_capacity(list.len());
    for (i, r) in list.into_iter().enumerate() {
        let side = match r.side.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None | Some("any") => Side::Any,
            Some("engine") | Some("only_in_engine") => Side::Engine,
            Some("reference") | Some("only_in_reference") => Side::Reference,
            Some("mismatch") => Side::Mismatch,
            Some(o) => bail!("rule {i}: side {o:?} is not engine|reference|mismatch|any"),
        };
        if let Some(f) = &r.field
            && !FIELDS.contains(&f.as_str())
        {
            bail!("rule {i}: field {f:?} is not one of {FIELDS:?}");
        }
        let re = Regex::new(&format!("(?i){}", r.pattern)).with_context(|| format!("rule {i}: match"))?;
        out.push(Rule { pattern: r.pattern, re, side, field: r.field, why: r.why });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------------------------

/// The compared fields, in report order.
pub const FIELDS: [&str; 7] = ["name", "version", "uninstall", "quiet", "sys", "parent", "product_code"];

/// Where a difference was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    OnlyInEngine,
    OnlyInReference,
    Mismatch,
}

/// The rule that explains a difference.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Explained {
    pub rule: usize,
    #[serde(rename = "match")]
    pub pattern: String,
    pub why: String,
}

/// One difference.
#[derive(Debug, Clone, Serialize)]
pub struct Diff {
    #[serde(skip)]
    pub kind: Kind,
    /// `key` (an Uninstall key) or `msi` (a product code).
    pub subject: &'static str,
    /// Canonical key path or product code.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<Value>,
    pub explained: Option<Explained>,
}

/// The comparison result.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub diffs: Vec<Diff>,
    pub engine_keys: usize,
    pub reference_keys: usize,
    pub matched_keys: usize,
    pub engine_msi: usize,
    pub reference_msi: Option<usize>,
    /// Field values equal only once the engine's `%VAR%` tokens are taken as wildcards.
    pub expanded: usize,
    /// Rules (by index) that explained nothing.
    pub unused_rules: Vec<usize>,
    /// Problems with the inputs themselves (duplicate keys).
    pub notes: Vec<String>,
}

impl Report {
    pub fn unexplained(&self) -> usize {
        self.diffs.iter().filter(|d| d.explained.is_none()).count()
    }
    pub fn of(&self, k: Kind) -> impl Iterator<Item = &Diff> {
        self.diffs.iter().filter(move |d| d.kind == k)
    }
    /// 0 when every difference is explained, else 1.
    pub fn exit_code(&self) -> i32 {
        if self.unexplained() == 0 { 0 } else { 1 }
    }
}

/// Engine value equals reference value, with `%VAR%` in the engine's value matching any text.
/// Returns `Some(expanded)` when equal (`expanded` = equal only through a wildcard), `None` when different.
fn str_eq(engine: Option<&str>, reference: Option<&str>, ci: bool) -> Option<bool> {
    match (engine, reference) {
        (None, None) => Some(false),
        (Some(e), Some(r)) => {
            if (ci && canon::ci_eq(e, r)) || e == r {
                return Some(false);
            }
            let var = Regex::new(r"%[A-Za-z0-9_()\-]+%").expect("static regex");
            if !var.is_match(e) || var.is_match(r) {
                return None;
            }
            let mut pat = String::from("(?s)^");
            if ci {
                pat.insert_str(0, "(?i)");
            }
            let mut last = 0;
            for m in var.find_iter(e) {
                pat.push_str(&regex::escape(&e[last..m.start()]));
                pat.push_str(".+?");
                last = m.end();
            }
            pat.push_str(&regex::escape(&e[last..]));
            pat.push('$');
            Regex::new(&pat).ok().filter(|re| re.is_match(r)).map(|_| true)
        }
        _ => None,
    }
}

fn opt_json(s: &Option<String>) -> Value {
    s.as_ref().map_or(Value::Null, |v| json!(v))
}

/// Compare the two sides and match every difference against `rules`.
pub fn compare(engine: &Engine, reference: &Reference, rules: &[Rule]) -> Report {
    let mut rep = Report {
        engine_keys: engine.rows.len(),
        reference_keys: reference.rows.len(),
        engine_msi: 0,
        reference_msi: reference.msi.as_ref().map(Vec::len),
        ..Report::default()
    };

    let index = |rows: &[Row], side: &str, notes: &mut Vec<String>| -> HashMap<CiString, usize> {
        let mut m = HashMap::new();
        for (i, r) in rows.iter().enumerate() {
            if m.insert(CiString::from(r.key.as_str()), i).is_some() {
                notes.push(format!("{side}: duplicate key {}", r.key));
            }
        }
        m
    };
    let eidx = index(&engine.rows, "engine", &mut rep.notes);
    let ridx = index(&reference.rows, "reference", &mut rep.notes);

    let mut diffs = Vec::new();
    let key_diff = |kind, r: &Row| Diff {
        kind,
        subject: "key",
        id: r.key.clone(),
        name: r.name.clone(),
        field: None,
        engine: None,
        reference: None,
        explained: None,
    };
    for r in &engine.rows {
        if !ridx.contains_key(CiStr::new(&r.key)) {
            diffs.push(key_diff(Kind::OnlyInEngine, r));
        }
    }
    for r in &reference.rows {
        if !eidx.contains_key(CiStr::new(&r.key)) {
            diffs.push(key_diff(Kind::OnlyInReference, r));
        }
    }

    // Field mismatches on keys present on both sides (first occurrence of a duplicate).
    let mut seen = HashMap::new();
    for e in &engine.rows {
        let Some(&ri) = ridx.get(CiStr::new(&e.key)) else {
            continue;
        };
        if seen.insert(CiString::from(e.key.as_str()), ()).is_some() {
            continue;
        }
        rep.matched_keys += 1;
        let r = &reference.rows[ri];
        let mut mismatch = |field: &'static str, ev: Value, rv: Value| {
            diffs.push(Diff {
                kind: Kind::Mismatch,
                subject: "key",
                id: e.key.clone(),
                name: e.name.clone(),
                field: Some(field),
                engine: Some(ev),
                reference: Some(rv),
                explained: None,
            });
        };
        let strs: [(&'static str, &Option<String>, &Option<String>, bool); 5] = [
            ("name", &e.name, &r.name, false),
            ("version", &e.version, &r.version, false),
            ("uninstall", &e.uninstall, &r.uninstall, false),
            ("quiet", &e.quiet, &r.quiet, false),
            ("parent", &e.parent, &r.parent, true),
        ];
        for (field, ev, rv, ci) in strs {
            match str_eq(ev.as_deref(), rv.as_deref(), ci) {
                Some(true) => rep.expanded += 1,
                Some(false) => {}
                None => mismatch(field, opt_json(ev), opt_json(rv)),
            }
        }
        if e.sys != r.sys {
            mismatch("sys", json!(e.sys), json!(r.sys));
        }
        if let (Some(ec), Some(rc)) = (&e.code, &r.code)
            && str_eq(ec.as_deref(), rc.as_deref(), true).is_none()
        {
            mismatch("product_code", opt_json(ec), opt_json(rc));
        }
    }

    // MSI product codes (sets: a per-user product installed for two users is one code).
    let mut ecodes: BTreeMap<String, Option<String>> = BTreeMap::new();
    for (c, n) in &engine.msi {
        ecodes.entry(c.clone()).or_insert_with(|| n.clone());
    }
    rep.engine_msi = ecodes.len();
    if let Some(rmsi) = &reference.msi {
        let rcodes: std::collections::BTreeSet<&str> = rmsi.iter().map(String::as_str).collect();
        rep.reference_msi = Some(rcodes.len());
        let msi_diff = |kind, id: &str, name: Option<String>| Diff {
            kind,
            subject: "msi",
            id: id.to_string(),
            name,
            field: None,
            engine: None,
            reference: None,
            explained: None,
        };
        for (c, n) in &ecodes {
            if !rcodes.contains(c.as_str()) {
                diffs.push(msi_diff(Kind::OnlyInEngine, c, n.clone()));
            }
        }
        for c in &rcodes {
            if !ecodes.contains_key(*c) {
                diffs.push(msi_diff(Kind::OnlyInReference, c, None));
            }
        }
    }

    // Explanations: first matching rule wins.
    let mut used = vec![false; rules.len()];
    for d in diffs.iter_mut() {
        for (i, rule) in rules.iter().enumerate() {
            let side_ok = match rule.side {
                Side::Any => true,
                Side::Engine => d.kind == Kind::OnlyInEngine,
                Side::Reference => d.kind == Kind::OnlyInReference,
                Side::Mismatch => d.kind == Kind::Mismatch,
            };
            let field_ok = match (&rule.field, d.field) {
                (None, _) => true,
                (Some(f), Some(df)) => f == df,
                (Some(_), None) => false,
            };
            if side_ok && field_ok && rule.re.is_match(&d.id) {
                d.explained = Some(Explained { rule: i, pattern: rule.pattern.clone(), why: rule.why.clone() });
                used[i] = true;
                break;
            }
        }
    }
    rep.unused_rules = used.iter().enumerate().filter(|(_, u)| !**u).map(|(i, _)| i).collect();
    rep.diffs = diffs;
    rep
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

/// Arguments of `rigtool invdiff`.
pub struct InvdiffArgs {
    pub inv: PathBuf,
    pub lists: PathBuf,
    pub explain: Option<PathBuf>,
    pub sid: Option<String>,
    pub json: Option<PathBuf>,
    pub md: Option<PathBuf>,
}

fn read_value(p: &Path) -> Result<Value> {
    let t = jsonio::read_text(p)?;
    serde_json::from_str(&t).with_context(|| format!("parse {}", p.display()))
}

/// The JSON report.
pub fn report_json(rep: &Report, a: &InvdiffArgs, reference: &Reference, rules: &[Rule]) -> Value {
    let list = |k| rep.of(k).cloned().collect::<Vec<_>>();
    json!({
        "schema": SCHEMA,
        "inventory": a.inv.display().to_string(),
        "lists": a.lists.display().to_string(),
        "lists_shape": reference.shape,
        "explain": a.explain.as_ref().map(|p| p.display().to_string()),
        "sid": reference.sid,
        "msi_compared": reference.msi.is_some(),
        "counts": {
            "engine_keys": rep.engine_keys,
            "reference_keys": rep.reference_keys,
            "matched_keys": rep.matched_keys,
            "engine_msi": rep.engine_msi,
            "reference_msi": rep.reference_msi,
            "expanded": rep.expanded,
        },
        "summary": {
            "only_in_engine": rep.of(Kind::OnlyInEngine).count(),
            "only_in_reference": rep.of(Kind::OnlyInReference).count(),
            "mismatches": rep.of(Kind::Mismatch).count(),
            "explained": rep.diffs.len() - rep.unexplained(),
            "unexplained": rep.unexplained(),
        },
        "only_in_engine": list(Kind::OnlyInEngine),
        "only_in_reference": list(Kind::OnlyInReference),
        "mismatches": list(Kind::Mismatch),
        "unused_rules": rep.unused_rules.iter().map(|&i| json!({"rule": i, "match": rules[i].pattern, "why": rules[i].why})).collect::<Vec<_>>(),
        "notes": rep.notes,
    })
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn cell(v: &Option<Value>) -> String {
    match v {
        None => String::new(),
        Some(Value::String(s)) => format!("`{}`", md_escape(s)),
        Some(Value::Null) => "-".to_string(),
        Some(o) => md_escape(&o.to_string()),
    }
}

/// The Markdown report: counts, then unexplained and explained differences.
pub fn report_md(rep: &Report, reference: &Reference) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Inventory equality check\n");
    let _ = writeln!(s, "| | engine | reference |\n|---|---:|---:|");
    let _ = writeln!(s, "| Uninstall keys | {} | {} |", rep.engine_keys, rep.reference_keys);
    let rm = rep.reference_msi.map_or("not compared".to_string(), |n| n.to_string());
    let _ = writeln!(s, "| MSI product codes | {} | {} |\n", rep.engine_msi, rm);
    let _ = writeln!(
        s,
        "Lists shape `{}`, {} keys on both sides, {} values equal after `%VAR%` expansion.\n",
        match reference.shape {
            Shape::Lists => "lists",
            Shape::Legacy => "legacy",
        },
        rep.matched_keys,
        rep.expanded
    );
    let _ = writeln!(
        s,
        "Differences: {} only in engine, {} only in reference, {} mismatches; **{} unexplained**.\n",
        rep.of(Kind::OnlyInEngine).count(),
        rep.of(Kind::OnlyInReference).count(),
        rep.of(Kind::Mismatch).count(),
        rep.unexplained()
    );
    for (title, explained) in [("Unexplained", false), ("Explained", true)] {
        let rows: Vec<&Diff> = rep.diffs.iter().filter(|d| d.explained.is_some() == explained).collect();
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(s, "## {title}\n");
        let _ = writeln!(s, "| kind | subject | id | name | field | engine | reference | why |");
        let _ = writeln!(s, "|---|---|---|---|---|---|---|---|");
        for d in rows {
            let kind = match d.kind {
                Kind::OnlyInEngine => "only in engine",
                Kind::OnlyInReference => "only in reference",
                Kind::Mismatch => "mismatch",
            };
            let why = d.explained.as_ref().map_or(String::new(), |e| format!("rule {}: {}", e.rule, md_escape(&e.why)));
            let _ = writeln!(
                s,
                "| {kind} | {} | `{}` | {} | {} | {} | {} | {why} |",
                d.subject,
                md_escape(&d.id),
                md_escape(d.name.as_deref().unwrap_or("")),
                d.field.unwrap_or(""),
                cell(&d.engine),
                cell(&d.reference),
            );
        }
        let _ = writeln!(s);
    }
    for n in &rep.notes {
        let _ = writeln!(s, "- note: {}", md_escape(n));
    }
    s
}

/// `rigtool invdiff`. Writes the reports and returns the comparison (see [`Report::exit_code`]).
pub fn cmd_invdiff(a: &InvdiffArgs) -> Result<Report> {
    let lists = read_value(&a.lists)?;
    let reference = parse_reference(&lists, a.sid.as_deref()).with_context(|| a.lists.display().to_string())?;
    if reference.sid.is_none() && reference.rows.iter().any(|r| r.key.starts_with("HKCU")) {
        eprintln!("invdiff: warning: HKEY_CURRENT_USER keys and no --sid; they cannot match the engine's HKU keys");
    }
    let engine =
        parse_engine(read_value(&a.inv)?, reference.sid.as_deref()).with_context(|| a.inv.display().to_string())?;
    let rules = match &a.explain {
        Some(p) => parse_rules(read_value(p)?).with_context(|| p.display().to_string())?,
        None => Vec::new(),
    };
    let rep = compare(&engine, &reference, &rules);
    if let Some(p) = &a.json {
        jsonio::write(p, &report_json(&rep, a, &reference, &rules))?;
    }
    let md = report_md(&rep, &reference);
    match &a.md {
        Some(p) => std::fs::write(p, md).with_context(|| format!("write {}", p.display()))?,
        None => print!("{md}"),
    }
    eprintln!(
        "invdiff: {} keys engine / {} reference, {} differences, {} unexplained",
        rep.engine_keys,
        rep.reference_keys,
        rep.diffs.len(),
        rep.unexplained()
    );
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const UN: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    const MSI_X: &str = "{AAAAAAAA-0000-0000-0000-000000000001}";

    fn entry(key_path: &str, name: &str, code: Option<&str>, msi: bool) -> Value {
        json!({
            "program_id": "x", "key_path": key_path, "hive_sid": null, "view": "K64",
            "display_name": name, "version": "1.0", "publisher": null,
            "flags": {"system_component": false, "has_display_name": true, "has_uninstall_string": true,
                      "parent_key": null, "release_type": null, "windows_installer": code.is_some()},
            "installer_kind": "Unknown", "scope": "Machine", "product_code": code, "upgrade_code": null,
            "inno_app_id": null, "writable_by": "admin", "install_location": null,
            "uninstall_string": "\"%ProgramFiles%\\App\\u.exe\"", "quiet_uninstall_string": null,
            "display_icon": null, "install_time_evidence": [],
            "msi": if msi { json!({"context": "Machine", "local_package": null, "install_date": null}) } else { Value::Null }
        })
    }

    fn row(key: &str, name: &str, msi: Option<&str>) -> Value {
        json!({"key": key, "name": name, "version": "1.0", "publisher": null, "sys": false, "parent": null,
               "uninstall": "\"C:\\Program Files\\App\\u.exe\"", "quiet": null, "loc": null, "icon": null,
               "msi": msi, "size": null, "install_date": null, "bundle": false})
    }

    fn hklm(leaf: &str) -> String {
        format!("HKLM\\{UN}\\{leaf}")
    }

    /// Engine and lists for the same machine: A (plain), B (MSI product M).
    fn synthetic() -> (Value, Value) {
        let m = "{BBBBBBBB-0000-0000-0000-000000000002}";
        let inv = json!({"schema": "purge.inventory/0", "entries": [
            entry(&hklm("A"), "App A", None, false),
            entry(&hklm(m), "Product M", Some(m), true),
        ], "msi_only": []});
        let lists = json!({"schema": "x", "user_sid": SID,
            "uninstall": [
                row(&format!("HKEY_LOCAL_MACHINE\\{UN}\\A"), "App A ", None),
                row(&hklm(m), "Product M", Some(&m.to_ascii_lowercase())),
            ],
            // PowerShell writes a one-element array as the element itself.
            "msi": {"code": m, "name": "Product M", "version": "1", "context": "machine"}});
        (inv, lists)
    }

    fn run(inv: Value, lists: Value, rules: Value, sid: Option<&str>) -> Report {
        let r = parse_reference(&lists, sid).unwrap();
        let e = parse_engine(inv, r.sid.as_deref()).unwrap();
        compare(&e, &r, &parse_rules(rules).unwrap())
    }

    /// The same machine plus one HKCU-only key, one MSI product without ARP key and one renamed entry.
    fn with_three_differences() -> (Value, Value) {
        let (mut inv, mut lists) = synthetic();
        inv["entries"][0]["display_name"] = json!("App A 2");
        inv["msi_only"] = json!([{"product_code": MSI_X, "context": "Machine", "user_sid": null,
            "product_name": "Hidden Runtime", "version": "1", "publisher": null, "install_location": null,
            "local_package": null, "install_date": null}]);
        lists["uninstall"].as_array_mut().unwrap().push(row(
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\UserApp",
            "User App",
            None,
        ));
        (inv, lists)
    }

    #[test]
    fn synthetic_pair_has_no_differences() {
        let (inv, lists) = synthetic();
        let rep = run(inv, lists, json!([]), None);
        assert!(rep.diffs.is_empty(), "{:?}", rep.diffs);
        assert_eq!(rep.matched_keys, 2);
        assert_eq!(rep.engine_msi, 1);
        assert_eq!(rep.reference_msi, Some(1));
        // the engine's %ProgramFiles% matched the rig's expanded value, twice
        assert_eq!(rep.expanded, 2);
        assert_eq!(rep.exit_code(), 0);
    }

    #[test]
    fn lists_exactly_the_three_differences() {
        let (inv, lists) = with_three_differences();
        let rep = run(inv, lists, json!({"rules": []}), None);
        let got: Vec<(Kind, &str, Option<&str>)> = rep.diffs.iter().map(|d| (d.kind, d.id.as_str(), d.field)).collect();
        let user_key = format!("HKU\\{SID}\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\UserApp");
        assert_eq!(
            got,
            vec![
                (Kind::OnlyInReference, user_key.as_str(), None),
                (Kind::Mismatch, hklm("A").as_str(), Some("name")),
                (Kind::OnlyInEngine, MSI_X, None),
            ]
        );
        let ren = rep.of(Kind::Mismatch).next().unwrap();
        assert_eq!(ren.engine, Some(json!("App A 2")));
        assert_eq!(ren.reference, Some(json!("App A")));
        assert_eq!(rep.exit_code(), 1);
    }

    #[test]
    fn exit_code_follows_the_explanations() {
        let rules = json!({"rules": [
            {"match": "^HKU\\\\S-1-5-21-[^\\\\]+\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\UserApp$",
             "side": "reference", "why": "per-user key the engine did not read"},
            {"match": "^\\{AAAAAAAA-", "side": "engine", "why": "advertised product"},
            {"match": "Uninstall\\\\A$", "side": "mismatch", "field": "name", "why": "renamed between captures"},
            {"match": "never", "why": "unused"}
        ]});
        let (inv, lists) = with_three_differences();
        let rep = run(inv.clone(), lists.clone(), rules.clone(), None);
        assert_eq!(rep.unexplained(), 0);
        assert_eq!(rep.exit_code(), 0);
        assert_eq!(rep.unused_rules, vec![3]);
        assert_eq!(rep.diffs[1].explained.as_ref().unwrap().rule, 2);

        // Drop the rename rule: one difference left unexplained.
        let mut partial = rules.clone();
        partial["rules"].as_array_mut().unwrap().remove(2);
        let rep = run(inv.clone(), lists.clone(), partial, None);
        assert_eq!(rep.unexplained(), 1);
        assert_eq!(rep.exit_code(), 1);

        // Side and field restrict a rule: an "engine" rule never explains a reference-only key, and a
        // field rule never explains another field.
        let wrong = json!([
            {"match": "UserApp", "side": "engine", "why": "x"},
            {"match": "^\\{AAAAAAAA-", "side": "reference", "why": "x"},
            {"match": "Uninstall\\\\A$", "field": "version", "why": "x"}
        ]);
        let rep = run(inv, lists, wrong, None);
        assert_eq!(rep.unexplained(), 3);
    }

    #[test]
    fn rule_validation() {
        assert!(parse_rules(json!([{"match": "(", "why": "x"}])).is_err());
        assert!(parse_rules(json!([{"match": "x", "side": "left", "why": "x"}])).is_err());
        assert!(parse_rules(json!([{"match": "x", "field": "size", "why": "x"}])).is_err());
        assert!(parse_rules(json!([{"match": "x"}])).is_err());
        let r = parse_rules(json!({"rules": [{"match": "x", "side": "only_in_engine", "why": "y"}]})).unwrap();
        assert_eq!(r[0].side, Side::Engine);
    }

    #[test]
    fn field_mismatches() {
        let (mut inv, mut lists) = synthetic();
        let e = &mut inv["entries"][0];
        e["version"] = json!("2.0");
        e["quiet_uninstall_string"] = json!("u.exe /S");
        e["flags"]["system_component"] = json!(true);
        e["flags"]["parent_key"] = json!("Parent");
        inv["entries"][1]["product_code"] = json!("{CCCCCCCC-0000-0000-0000-000000000003}");
        lists["uninstall"][0]["uninstall"] = json!("C:\\Other\\u.exe");
        lists["uninstall"][0]["parent"] = json!("PARENT"); // case-insensitive: equal
        let rep = run(inv, lists, json!([]), None);
        let fields: Vec<&str> = rep.of(Kind::Mismatch).map(|d| d.field.unwrap()).collect();
        assert_eq!(fields, vec!["version", "uninstall", "quiet", "sys", "product_code"]);
        // the engine's code changed, so the MSI sets differ too
        assert_eq!(rep.of(Kind::OnlyInEngine).count(), 1);
        assert_eq!(rep.of(Kind::OnlyInReference).count(), 1);
    }

    #[test]
    fn missing_reference_name_is_the_key_name() {
        let inv = json!({"schema": "purge.inventory/0", "entries": [entry(&hklm("AddressBook"), "AddressBook", None, false)]});
        let lists = json!({"uninstall": [{"key": hklm("AddressBook"), "name": null, "version": 1.0,
            "sys": 0, "uninstall": " \"C:\\Program Files\\App\\u.exe\" ", "msi": null}], "msi": null});
        let rep = run(inv, lists, json!([]), None);
        assert!(rep.diffs.is_empty(), "{:?}", rep.diffs);
    }

    #[test]
    fn str_eq_wildcards() {
        assert_eq!(str_eq(Some("a"), Some("a"), false), Some(false));
        assert_eq!(str_eq(None, None, false), Some(false));
        assert_eq!(str_eq(Some("a"), None, false), None);
        assert_eq!(str_eq(Some("%SystemRoot%\\x.exe"), Some("C:\\Windows\\x.exe"), false), Some(true));
        assert_eq!(str_eq(Some("%SystemRoot%\\x.exe"), Some("C:\\Windows\\y.exe"), false), None);
        // both unexpanded and different: no wildcard
        assert_eq!(str_eq(Some("%A%\\x"), Some("%B%\\x"), false), None);
        assert_eq!(str_eq(Some("{abc}"), Some("{ABC}"), true), Some(false));
        assert_eq!(str_eq(Some("Abc"), Some("abc"), false), None);
    }

    #[test]
    fn hkcu_canonicalisation_needs_a_sid() {
        let lists = json!([{"key": "HKEY_CURRENT_USER\\Software\\X", "name": "x"}]);
        let r = parse_reference(&lists, Some(SID)).unwrap();
        assert_eq!(r.rows[0].key, format!("HKU\\{SID}\\Software\\X"));
        let r = parse_reference(&lists, None).unwrap();
        assert_eq!(r.rows[0].key, "HKCU\\Software\\X");
        // --sid wins over the file's user_sid
        let lists = json!({"user_sid": "S-1-5-21-9", "uninstall": [{"key": "HKCU\\Software\\X"}]});
        assert_eq!(parse_reference(&lists, Some(SID)).unwrap().rows[0].key, format!("HKU\\{SID}\\Software\\X"));
        assert_eq!(parse_reference(&lists, None).unwrap().rows[0].key, "HKU\\S-1-5-21-9\\Software\\X");
    }

    #[test]
    fn shapes() {
        let (_, lists) = synthetic();
        let r = parse_reference(&lists, None).unwrap();
        assert_eq!(r.shape, Shape::Lists);
        assert_eq!(r.msi.as_deref(), Some(&["{BBBBBBBB-0000-0000-0000-000000000002}".to_string()][..]));
        assert_eq!(r.rows[1].code, Some(Some("{BBBBBBBB-0000-0000-0000-000000000002}".to_string())));
        // single uninstall row written as an object, msi as null
        let r = parse_reference(&json!({"uninstall": {"key": "HKLM\\X"}, "msi": null}), None).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.msi, Some(vec![]));
        assert!(parse_reference(&json!({"msi": []}), None).is_err());
        assert!(parse_reference(&json!("x"), None).is_err());
        // the engine document needs its schema
        assert!(parse_engine(json!({"schema": "purge.plan/0", "entries": []}), None).is_err());
    }

    #[test]
    fn legacy_shape_skips_msi() {
        let (inv, _) = synthetic();
        let legacy = json!([
            {"key": format!("HKEY_LOCAL_MACHINE\\{UN}\\A"), "name": "App A", "version": "1.0", "sys": null,
             "parent": null, "uninstall": "\"C:\\Program Files\\App\\u.exe\"", "quiet": null, "size": 5, "loc": null},
            {"key": hklm("{BBBBBBBB-0000-0000-0000-000000000002}"), "name": "Product M", "version": "1.0", "sys": 1,
             "parent": null, "uninstall": "\"C:\\Program Files\\App\\u.exe\"", "quiet": null, "size": null, "loc": null}
        ]);
        let rep = run(inv, legacy, json!([]), None);
        assert_eq!(rep.reference_msi, None);
        // only the SystemComponent difference; product codes are not compared
        let d: Vec<_> = rep.diffs.iter().map(|d| (d.kind, d.field)).collect();
        assert_eq!(d, vec![(Kind::Mismatch, Some("sys"))]);
    }

    #[test]
    fn committed_legacy_registry_list_parses() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../results/lists-registry.json");
        if !p.exists() {
            eprintln!("skipping: {} is gitignored and absent in this checkout", p.display());
            return;
        }
        let v = read_value(&p).unwrap();
        let r = parse_reference(&v, Some(SID)).unwrap();
        assert_eq!(r.shape, Shape::Legacy);
        assert_eq!(r.rows.len(), 80);
        assert!(r.rows.iter().all(|x| x.key.starts_with("HKLM\\") || x.key.starts_with(&format!("HKU\\{SID}\\"))));
    }

    #[test]
    fn committed_explanations_parse() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../truth/inventory-explain.json");
        let rules = parse_rules(read_value(&p).unwrap()).unwrap();
        assert!(!rules.is_empty());
        // engine-only service and .DEFAULT hives are explained, an interactive user's key is not
        let e = Engine {
            rows: vec![
                Row {
                    key: canon::canon_reg(
                        "HKU\\S-1-5-18\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X",
                        None,
                    ),
                    ..Row::default()
                },
                Row {
                    key: "HKU\\S-1-5-19\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X".to_string(),
                    ..Row::default()
                },
                Row {
                    key: format!("HKU\\{SID}\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X"),
                    ..Row::default()
                },
            ],
            msi: vec![],
        };
        let r = Reference { shape: Shape::Lists, rows: vec![], msi: Some(vec![]), sid: None };
        let rep = compare(&e, &r, &rules);
        assert_eq!(rep.unexplained(), 1);
        assert!(rep.diffs[2].explained.is_none());
    }

    #[test]
    fn duplicate_keys_are_noted() {
        let inv = json!({"schema": "purge.inventory/0", "entries": [
            entry(&hklm("A"), "App A", None, false), entry(&hklm("a"), "App A", None, false)]});
        let lists = json!({"uninstall": [row(&hklm("A"), "App A", None)], "msi": []});
        let rep = run(inv, lists, json!([]), None);
        assert_eq!(rep.notes.len(), 1);
        assert_eq!(rep.matched_keys, 1);
    }

    #[test]
    fn writes_reports() {
        let dir = std::env::temp_dir().join(format!("rigtool-invdiff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (inv, lists) = with_three_differences();
        let (pi, pl, pj, pm) = (dir.join("inv.json"), dir.join("lists.json"), dir.join("out.json"), dir.join("out.md"));
        jsonio::write(&pi, &inv).unwrap();
        // lists files written by PowerShell 5.1 carry a BOM
        std::fs::write(&pl, format!("\u{feff}{}", serde_json::to_string(&lists).unwrap())).unwrap();
        let a =
            InvdiffArgs { inv: pi, lists: pl, explain: None, sid: None, json: Some(pj.clone()), md: Some(pm.clone()) };
        let rep = cmd_invdiff(&a).unwrap();
        assert_eq!(rep.exit_code(), 1);
        let j: Value = jsonio::read(&pj).unwrap();
        assert_eq!(j["schema"], SCHEMA);
        assert_eq!(j["summary"]["unexplained"], 3);
        assert_eq!(j["only_in_engine"][0]["subject"], "msi");
        assert_eq!(j["mismatches"][0]["field"], "name");
        assert!(std::fs::read_to_string(&pm).unwrap().contains("**3 unexplained**"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
