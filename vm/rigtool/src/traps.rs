//! `rigtool traps` (M1b, C-RIG): scores a scan's plan against the scan-trap list `vm/truth/m1b-traps.json`
//! (`purge.m1b.traps/1`, planted by `vm/guest/m1b-traps.ps1`).
//!
//! Every expectation names a target (Target JSON as in the plan) and a verdict. Targets on both sides go through
//! the canonicalisation the scorer applies to plan targets ([`Target::canonical`]); two targets are *equal* when
//! their canonical strings are equal (case-insensitive). Beyond equality, a plan entry and an expectation are
//! related through their primitives ([`Target::primitives`]: a service is its `Services\<name>` key, a task its
//! file and `TaskCache\Tree` key, a firewall rule its `FirewallRules` value): the entry *covers* the target (a
//! listed ancestor directory or key, or the key of a listed value) or lies *inside* it.
//!
//! The plan entries are the items of a `purge.scan/0` document plus its `absorbed` candidates (deleted with their
//! Safe parent), or the items of a `purge.plan/0` document (which records no blockers).
//!
//! Verdicts (an escape fails `absent`, `protected` and `not_preselected`; a miss fails `listed` and `safe`):
//! - `absent`: no entry equal to the target, covering it or inside it, in any band.
//! - `protected`: every equal entry is Protected (band `Blocked`), not preselected, and carries the named blocker
//!   (a `purge.plan/0` records none, so a named blocker fails there); no covering or inside entry is actionable
//!   (band other than Blocked, action other than `ReportOnly`). Not listing it at all is no escape.
//! - `not_preselected`: no equal, covering or inside entry is preselected or Safe.
//! - `listed`: an equal entry, or a covering actionable entry, in a band other than Blocked.
//! - `safe`: an equal or covering entry in band Safe.
//!
//! Errors (exit code 2, never a pass): an unreadable input, a trap file with another schema, with zero cases or a
//! case with zero expectations, a duplicate case id, a blocker on a verdict other than `protected`, a plan whose
//! app is not the run's (`--app`), a target that names `HKCU` without a SID. Exit code 1 when escapes > 0 or
//! missed_owned > 0, else 0.

use crate::canon;
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::target::Target;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

pub const SCHEMA: &str = "purge.m1b.traps/1";
pub const OUT_SCHEMA: &str = "purge.rig.m1b-traps-score/1";

// ---------------------------------------------------------------------------------------------
// Trap file
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Absent,
    Protected,
    NotPreselected,
    Listed,
    Safe,
}

impl Verdict {
    fn name(self) -> &'static str {
        match self {
            Verdict::Absent => "absent",
            Verdict::Protected => "protected",
            Verdict::NotPreselected => "not_preselected",
            Verdict::Listed => "listed",
            Verdict::Safe => "safe",
        }
    }
    /// Failing this verdict is an escape (else a missed owned item).
    fn is_guard(self) -> bool {
        matches!(self, Verdict::Absent | Verdict::Protected | Verdict::NotPreselected)
    }
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pre,
    Post,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub target: Target,
    pub verdict: Verdict,
    #[serde(default)]
    pub blocker: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub phase: Phase,
    pub plant: String,
    pub expect: Vec<Expect>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TrapFile {
    pub schema: String,
    pub cases: Vec<Case>,
}

pub fn parse_traps(text: &str) -> Result<TrapFile> {
    let f: TrapFile = serde_json::from_str(text).context("trap file")?;
    if f.schema != SCHEMA {
        bail!("trap file: schema {:?}, want {SCHEMA}", f.schema);
    }
    if f.cases.is_empty() {
        bail!("trap file: zero cases (nothing would be checked)");
    }
    let mut ids = HashSet::new();
    for c in &f.cases {
        if c.id.trim().is_empty() {
            bail!("trap file: a case without an id");
        }
        if !ids.insert(c.id.to_ascii_lowercase()) {
            bail!("trap file: case id {:?} twice", c.id);
        }
        if c.expect.is_empty() {
            bail!("trap file: case {:?} has zero expectations (nothing would be checked)", c.id);
        }
        for e in &c.expect {
            if e.blocker.is_some() && e.verdict != Verdict::Protected {
                bail!("trap file: case {:?}: a blocker on verdict {}", c.id, e.verdict.name());
            }
            if e.blocker.as_deref().is_some_and(|b| b.trim().is_empty()) {
                bail!("trap file: case {:?}: an empty blocker name", c.id);
            }
        }
    }
    Ok(f)
}

// ---------------------------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------------------------

/// One listed item of the plan.
#[derive(Clone, Debug)]
pub struct Entry {
    pub target: Target,
    pub band: String,
    pub preselected: bool,
    pub action: Option<String>,
    /// Blocker kinds; `None` when the document does not record blockers (`purge.plan/0`).
    pub blockers: Option<Vec<String>>,
    /// A `purge.scan/0` absorbed candidate (removed with its Safe parent).
    pub absorbed: bool,
}

impl Entry {
    fn is_blocked(&self) -> bool {
        crate::score::is_protected_band(&self.band)
    }
    fn is_safe(&self) -> bool {
        self.band.eq_ignore_ascii_case("safe")
    }
    fn report_only(&self) -> bool {
        self.action.as_deref().is_some_and(|a| a.eq_ignore_ascii_case("ReportOnly"))
    }
    /// Can executing it take something away?
    fn actionable(&self) -> bool {
        !self.is_blocked() && !self.report_only()
    }
}

pub struct PlanDoc {
    pub schema: String,
    pub app: String,
    pub entries: Vec<Entry>,
}

fn str_of(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn target_of(v: &Value, what: &str) -> Result<Target> {
    let t = v.get("target").with_context(|| format!("{what}: no target"))?;
    serde_json::from_value(t.clone()).with_context(|| format!("{what}: target"))
}

pub fn parse_plan(text: &str) -> Result<PlanDoc> {
    let v: Value = serde_json::from_str(text).context("plan")?;
    let schema = str_of(&v, "schema").unwrap_or_default();
    let app = str_of(&v, "app").context("plan: no app")?;
    let mut entries = Vec::new();
    let arr = |k: &str| v.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    match schema.as_str() {
        "purge.scan/0" => {
            if !v.get("items").is_some_and(Value::is_array) {
                bail!("plan: purge.scan/0 without items");
            }
            for (absorbed, list) in [(false, arr("items")), (true, arr("absorbed"))] {
                for (i, c) in list.iter().enumerate() {
                    let what = format!("{}[{i}]", if absorbed { "absorbed" } else { "items" });
                    let target = target_of(c, &what)?;
                    // A candidate without a decision is written to purge.plan/0 as Blocked and unticked (emit.rs).
                    let (band, preselected) = match c.get("decision").filter(|d| !d.is_null()) {
                        Some(d) => (
                            str_of(d, "band").with_context(|| format!("{what}: decision without band"))?,
                            d.get("preselected").and_then(Value::as_bool).unwrap_or(false),
                        ),
                        None => ("Blocked".to_string(), false),
                    };
                    let blockers = c
                        .get("blockers")
                        .and_then(Value::as_array)
                        .map(|b| b.iter().filter_map(|x| str_of(x, "kind")).collect())
                        .unwrap_or_default();
                    entries.push(Entry {
                        target,
                        band,
                        preselected,
                        action: str_of(c, "action"),
                        blockers: Some(blockers),
                        absorbed,
                    });
                }
            }
        }
        "purge.plan/0" | "" => {
            if !v.get("items").is_some_and(Value::is_array) {
                bail!("plan: no items");
            }
            for (i, it) in arr("items").iter().enumerate() {
                let what = format!("items[{i}]");
                entries.push(Entry {
                    target: target_of(it, &what)?,
                    band: str_of(it, "band").unwrap_or_default(),
                    preselected: it.get("preselected").and_then(Value::as_bool).unwrap_or(false),
                    action: str_of(it, "action"),
                    blockers: None,
                    absorbed: false,
                });
            }
        }
        other => bail!("plan: schema {other:?}, want purge.scan/0 or purge.plan/0"),
    }
    Ok(PlanDoc { schema, app, entries })
}

// ---------------------------------------------------------------------------------------------
// Relations
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rel {
    Equal,
    /// The plan entry contains the target (deleting it deletes the target).
    Covers,
    /// The plan entry lies strictly inside the target (a partial removal).
    Inside,
}

impl Rel {
    fn name(self) -> &'static str {
        match self {
            Rel::Equal => "equal",
            Rel::Covers => "covers",
            Rel::Inside => "inside",
        }
    }
}

/// (container path or key, value name, segment) of a primitive; the first part is folded.
enum Prim {
    Path(String),
    Key(String),
    Value(String, String),
    Segment(String, String, String),
    Other(String),
}

fn prim(t: &Target) -> Prim {
    match t {
        Target::Path { path } => Prim::Path(canon::fold(path)),
        Target::RegKey { path } => Prim::Key(canon::fold(path)),
        Target::RegValue { path, name } | Target::RegValueChanged { path, name, .. } => {
            Prim::Value(canon::fold(path), name.to_lowercase())
        }
        Target::RegMultiSzSegment { path, name, segment } => {
            Prim::Segment(canon::fold(path), name.to_lowercase(), segment.trim().to_lowercase())
        }
        other => Prim::Other(canon::fold(&other.canon_string())),
    }
}

/// How plan primitive `e` relates to target primitive `t`.
fn prim_rel(e: &Prim, t: &Prim) -> Option<Rel> {
    let tree = |a: &str, b: &str| -> Option<Rel> {
        if a == b {
            Some(Rel::Equal)
        } else if canon::is_under_or_eq_folded(b, a) {
            Some(Rel::Covers)
        } else if canon::is_under_or_eq_folded(a, b) {
            Some(Rel::Inside)
        } else {
            None
        }
    };
    match (e, t) {
        (Prim::Path(a), Prim::Path(b)) | (Prim::Key(a), Prim::Key(b)) => tree(a, b),
        (Prim::Key(k), Prim::Value(tk, _) | Prim::Segment(tk, _, _)) => {
            canon::is_under_or_eq_folded(tk, k).then_some(Rel::Covers)
        }
        (Prim::Value(ek, _) | Prim::Segment(ek, _, _), Prim::Key(k)) => {
            canon::is_under_or_eq_folded(ek, k).then_some(Rel::Inside)
        }
        (Prim::Value(ak, an), Prim::Value(bk, bn)) => (ak == bk && an == bn).then_some(Rel::Equal),
        (Prim::Value(ak, an), Prim::Segment(bk, bn, _)) => (ak == bk && an == bn).then_some(Rel::Covers),
        (Prim::Segment(ak, an, _), Prim::Value(bk, bn)) => (ak == bk && an == bn).then_some(Rel::Inside),
        (Prim::Segment(ak, an, a), Prim::Segment(bk, bn, b)) => (ak == bk && an == bn && a == b).then_some(Rel::Equal),
        (Prim::Other(a), Prim::Other(b)) => (a == b).then_some(Rel::Equal),
        _ => None,
    }
}

/// The relation of a (canonical) plan target to a (canonical) expectation target, the strongest one found
/// (Equal > Covers > Inside).
pub fn relation(e: &Target, t: &Target) -> Option<Rel> {
    if canon::fold(&e.canon_string()) == canon::fold(&t.canon_string()) {
        return Some(Rel::Equal);
    }
    let mut best: Option<Rel> = None;
    let rank = |r: Rel| match r {
        Rel::Equal => 0,
        Rel::Covers => 1,
        Rel::Inside => 2,
    };
    for pe in e.primitives() {
        for pt in t.primitives() {
            if let Some(r) = prim_rel(&prim(&pe), &prim(&pt))
                && best.is_none_or(|b| rank(r) < rank(b))
            {
                best = Some(r);
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct Listing {
    pub target: String,
    pub relation: String,
    pub band: String,
    pub preselected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// `null` = the plan document records no blockers.
    pub blockers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub absorbed: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct ExpectRow {
    pub target: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    /// `pass`, `escape` or `missed_owned`.
    pub result: String,
    pub listed: bool,
    pub why: Vec<String>,
    pub listings: Vec<Listing>,
}

#[derive(Serialize, Clone, Debug)]
pub struct CaseRow {
    pub id: String,
    pub phase: String,
    pub plant: String,
    pub pass: bool,
    pub expectations: Vec<ExpectRow>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub cases: usize,
    pub expectations: usize,
    pub passed: usize,
    pub escapes: usize,
    pub missed_owned: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct TrapsReport {
    pub schema: String,
    pub plan: String,
    pub plan_schema: String,
    pub traps: String,
    pub app: String,
    pub sid: Option<String>,
    pub ok: bool,
    pub summary: Summary,
    pub cases: Vec<CaseRow>,
}

fn check_hkcu(t: &Target, what: &str) -> Result<()> {
    let p = t.path();
    if t.kind().starts_with("Reg") && (p.eq_ignore_ascii_case("HKCU") || canon::fold(p).starts_with("hkcu\\")) {
        bail!("{what}: {} names HKCU but no SID is known (--sid)", t.canon_string());
    }
    Ok(())
}

fn judge(e: &Expect, rel: &[(Rel, &Entry)]) -> (bool, Vec<String>) {
    let mut why = Vec::new();
    let tag = |r: Rel, x: &Entry| format!("{} {} ({})", r.name(), x.target.canon_string(), x.band);
    match e.verdict {
        Verdict::Absent => {
            for (r, x) in rel {
                why.push(format!("listed: {}", tag(*r, x)));
            }
        }
        Verdict::Protected => {
            for (r, x) in rel {
                if *r == Rel::Equal {
                    if !x.is_blocked() || x.absorbed {
                        why.push(format!(
                            "listed below Protected: {}{}",
                            tag(*r, x),
                            if x.absorbed { ", absorbed by a Safe parent" } else { "" }
                        ));
                    }
                    if x.preselected {
                        why.push(format!("preselected: {}", tag(*r, x)));
                    }
                    if let Some(b) = &e.blocker {
                        match &x.blockers {
                            None => why.push(format!("blocker {b} not verifiable: the plan records no blockers")),
                            Some(bs) if !bs.iter().any(|k| k.eq_ignore_ascii_case(b)) => {
                                why.push(format!("blocker {b} missing (has: {})", bs.join(", ")))
                            }
                            _ => {}
                        }
                    }
                } else if x.actionable() || x.preselected {
                    why.push(format!("actionable entry {}", tag(*r, x)));
                }
            }
        }
        Verdict::NotPreselected => {
            for (r, x) in rel {
                if x.preselected || x.is_safe() {
                    why.push(format!("{}: {}", if x.preselected { "preselected" } else { "Safe" }, tag(*r, x)));
                }
            }
        }
        Verdict::Listed => {
            let ok = rel.iter().any(|(r, x)| match r {
                Rel::Equal => !x.is_blocked() && !x.report_only(),
                Rel::Covers => x.actionable(),
                Rel::Inside => false,
            });
            if !ok {
                why.push(if rel.is_empty() {
                    "not listed".to_string()
                } else {
                    format!(
                        "not listed as removable (only {})",
                        rel.iter().map(|(r, x)| tag(*r, x)).collect::<Vec<_>>().join("; ")
                    )
                });
            }
        }
        Verdict::Safe => {
            let ok = rel.iter().any(|(r, x)| matches!(r, Rel::Equal | Rel::Covers) && x.is_safe() && !x.report_only());
            if !ok {
                why.push(if rel.is_empty() {
                    "not listed".to_string()
                } else {
                    format!(
                        "not listed Safe (only {})",
                        rel.iter().map(|(r, x)| tag(*r, x)).collect::<Vec<_>>().join("; ")
                    )
                });
            }
        }
    }
    (why.is_empty(), why)
}

pub fn score(plan: &PlanDoc, traps: &TrapFile, app: &str, sid: Option<&str>) -> Result<(Summary, Vec<CaseRow>)> {
    if plan.app != app {
        bail!("plan app {:?} is not the run's app {app:?}", plan.app);
    }
    let entries: Vec<Entry> =
        plan.entries.iter().map(|x| Entry { target: x.target.canonical(sid), ..x.clone() }).collect();
    for (i, x) in entries.iter().enumerate() {
        check_hkcu(&x.target, &format!("plan entry {i}"))?;
    }
    let mut sum = Summary { cases: traps.cases.len(), ..Default::default() };
    let mut rows = Vec::new();
    for c in &traps.cases {
        let mut ex_rows = Vec::new();
        for e in &c.expect {
            let t = e.target.canonical(sid);
            check_hkcu(&t, &format!("case {}", c.id))?;
            let rel: Vec<(Rel, &Entry)> =
                entries.iter().filter_map(|x| relation(&x.target, &t).map(|r| (r, x))).collect();
            let (ok, why) = judge(e, &rel);
            sum.expectations += 1;
            let result = if ok {
                sum.passed += 1;
                "pass"
            } else if e.verdict.is_guard() {
                sum.escapes += 1;
                "escape"
            } else {
                sum.missed_owned += 1;
                "missed_owned"
            };
            ex_rows.push(ExpectRow {
                target: t.canon_string(),
                verdict: e.verdict.name().to_string(),
                blocker: e.blocker.clone(),
                result: result.to_string(),
                listed: rel.iter().any(|(r, _)| *r == Rel::Equal),
                why,
                listings: rel
                    .iter()
                    .map(|(r, x)| Listing {
                        target: x.target.canon_string(),
                        relation: r.name().to_string(),
                        band: x.band.clone(),
                        preselected: x.preselected,
                        action: x.action.clone(),
                        blockers: x.blockers.clone(),
                        absorbed: x.absorbed,
                    })
                    .collect(),
            });
        }
        rows.push(CaseRow {
            id: c.id.clone(),
            phase: match c.phase {
                Phase::Pre => "pre",
                Phase::Post => "post",
            }
            .to_string(),
            plant: c.plant.clone(),
            pass: ex_rows.iter().all(|r| r.result == "pass"),
            expectations: ex_rows,
        });
    }
    Ok((sum, rows))
}

pub struct TrapsArgs {
    pub plan: PathBuf,
    pub traps: PathBuf,
    pub app: String,
    pub sid: Option<String>,
    pub out: PathBuf,
}

/// Runs the command. `Err` = an input error (exit code 2); `Ok(report)` with `ok == false` = escapes or missed
/// owned items (exit code 1).
pub fn cmd_traps(a: &TrapsArgs) -> Result<TrapsReport> {
    let traps = parse_traps(&jsonio::read_text(&a.traps)?).with_context(|| a.traps.display().to_string())?;
    let plan = parse_plan(&jsonio::read_text(&a.plan)?).with_context(|| a.plan.display().to_string())?;
    let (summary, cases) = score(&plan, &traps, &a.app, a.sid.as_deref())?;
    let rep = TrapsReport {
        schema: OUT_SCHEMA.to_string(),
        plan: a.plan.display().to_string(),
        plan_schema: plan.schema.clone(),
        traps: a.traps.display().to_string(),
        app: a.app.clone(),
        sid: a.sid.clone(),
        ok: summary.escapes == 0 && summary.missed_owned == 0,
        summary,
        cases,
    };
    jsonio::write(&a.out, &rep)?;
    for c in rep.cases.iter().filter(|c| !c.pass) {
        for e in c.expectations.iter().filter(|e| e.result != "pass") {
            eprintln!("traps: {} {} {} {}: {}", c.id, e.result, e.verdict, e.target, e.why.join("; "));
        }
    }
    let s = &rep.summary;
    eprintln!(
        "traps: cases {}  expectations {}  passed {}  escapes {}  missed_owned {} -> {}",
        s.cases,
        s.expectations,
        s.passed,
        s.escapes,
        s.missed_owned,
        a.out.display()
    );
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(p: &str) -> Target {
        Target::RegKey { path: p.into() }
    }

    #[test]
    fn relations_through_primitives() {
        let svc = Target::Service { name: "PurgeTrapSvc".into() };
        let key = k("HKLM\\SYSTEM\\CurrentControlSet\\Services\\PurgeTrapSvc");
        assert_eq!(relation(&key, &svc), Some(Rel::Equal));
        assert_eq!(relation(&k("HKLM\\SYSTEM\\CurrentControlSet\\Services"), &svc), Some(Rel::Covers));
        assert_eq!(relation(&k(&format!("{}\\Parameters", key.path())), &svc), Some(Rel::Inside));
        let v = Target::RegValue { path: "HKLM\\SOFTWARE\\X".into(), name: "A".into() };
        assert_eq!(relation(&k("hklm\\software"), &v), Some(Rel::Covers));
        assert_eq!(relation(&v, &k("HKLM\\SOFTWARE\\X")), Some(Rel::Inside));
        assert_eq!(
            relation(&Target::RegValue { path: "HKLM\\SOFTWARE\\X".into(), name: "a".into() }, &v),
            Some(Rel::Equal)
        );
        assert_eq!(relation(&Target::RegValue { path: "HKLM\\SOFTWARE\\X".into(), name: "B".into() }, &v), None);
        assert_eq!(relation(&k("HKLM\\SOFTWARE\\Xy"), &k("HKLM\\SOFTWARE\\X")), None);
        let fw = Target::FirewallRule { id: "{R}".into() };
        assert_eq!(relation(&fw, &fw), Some(Rel::Equal));
        let task = Target::Task { path: "\\Vendor\\Up".into() };
        assert_eq!(
            relation(&Target::Path { path: "C:\\Windows\\System32\\Tasks\\Vendor".into() }, &task),
            Some(Rel::Covers)
        );
    }

    #[test]
    fn parse_rejects_bad_files() {
        let ok = r#"{"schema":"purge.m1b.traps/1","cases":[{"id":"a","phase":"pre","plant":"P","expect":[{"target":{"type":"Service","name":"S"},"verdict":"absent","blocker":null}]}]}"#;
        assert!(parse_traps(ok).is_ok());
        for bad in [
            ok.replace("purge.m1b.traps/1", "purge.m1b.traps/2"),
            r#"{"schema":"purge.m1b.traps/1","cases":[]}"#.to_string(),
            ok.replace(
                r#""expect":[{"target":{"type":"Service","name":"S"},"verdict":"absent","blocker":null}]"#,
                r#""expect":[]"#,
            ),
            ok.replace("\"absent\",\"blocker\":null", "\"absent\",\"blocker\":\"SharedRefcount\""),
            ok.replace("\"absent\"", "\"gone\""),
            ok.replace("\"phase\":\"pre\"", "\"phase\":\"between\""),
            ok.replace("\"plant\":\"P\"", "\"plant\":\"P\",\"extra\":1"),
        ] {
            assert!(parse_traps(&bad).is_err(), "{bad}");
        }
        let twice = ok.replace("}]}]}", "}]},{\"id\":\"A\",\"phase\":\"post\",\"plant\":\"Q\",\"expect\":[{\"target\":{\"type\":\"Service\",\"name\":\"S\"},\"verdict\":\"absent\"}]}]}");
        assert!(parse_traps(&twice).is_err());
    }
}
