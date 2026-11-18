//! Ambient set (RIG.md §6): Windows churn seen in null runs, exact and generalized.

use crate::canon::{self};
use crate::diff::{self, Change};
use crate::err::{Context, Result};
use crate::items::{self, RigRules};
use crate::jsonio;
use crate::snap::{self, LoadOpts, Snap};
use crate::target::Target;
use regex::{Regex, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AmbientRunJson {
    pub id: String,
    #[serde(default)]
    pub dir: String,
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AmbientJson {
    #[serde(default)]
    pub schema: String,
    pub runs: Vec<AmbientRunJson>,
    pub exact: Vec<String>,
    pub patterns: Vec<String>,
}

fn token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?P<guid>\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?)|(?P<hex>[0-9A-Fa-f]{16,})|(?P<num>[0-9]{6,})",
        )
        .unwrap()
    })
}

const W_GUID: &str = r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?";
const W_HEX: &str = r"[0-9a-f]{16,}";
const W_NUM: &str = r"[0-9]{6,}";

/// Registration roots: a GUID directly under one of these keys names one COM class, interface, AppID or type
/// library. Null runs that register COM objects show several such GUIDs under the same root, but a wildcard there
/// would label every app's registration (an app's own CLSID leftover) as ambient, so these GUIDs stay literal.
fn reg_root_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(?:^|\\|_)Classes\\(?:WOW6432Node\\)?(?:CLSID|Interface|AppID|TypeLib)\\$").unwrap()
    })
}

fn kind_key(kind: &str) -> &str {
    if kind == "C" { "V" } else { kind }
}

/// The parent of each GUID in a canonical target string: kind plus the text before the GUID, with hex runs and
/// long numbers (always wildcards) normalised and earlier GUIDs kept literal. Returns (parent key, folded GUID).
fn guid_slots(cs: &str) -> Vec<(String, String)> {
    let Some((kind, body)) = cs.split_once(':') else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut key = format!("{}:", kind_key(kind));
    let mut last = 0;
    for c in token_re().captures_iter(body) {
        let m = c.get(0).unwrap();
        key.push_str(&canon::fold(&body[last..m.start()]));
        if c.name("guid").is_some() {
            let g = canon::fold(m.as_str().trim_start_matches('{').trim_end_matches('}'));
            out.push((key.clone(), g.clone()));
            key.push_str(&g);
        } else {
            key.push_str(if c.name("hex").is_some() { "\u{1}hex" } else { "\u{1}num" });
        }
        last = m.end();
    }
    out
}

/// Which GUID positions the null runs show as random: a GUID becomes a wildcard only when at least two different
/// GUIDs were seen under the same parent (same kind, same text before it), and never directly under a
/// registration root (`reg_root_re`).
#[derive(Default)]
pub struct GuidVariation {
    seen: std::collections::HashMap<String, HashSet<String>>,
}

impl GuidVariation {
    pub fn from_items<'a>(items: impl IntoIterator<Item = &'a String>) -> GuidVariation {
        let mut v = GuidVariation::default();
        for cs in items {
            for (k, g) in guid_slots(cs) {
                v.seen.entry(k).or_default().insert(g);
            }
        }
        v
    }

    fn varies(&self, key: &str) -> bool {
        self.seen.get(key).is_some_and(|s| s.len() >= 2)
    }
}

/// A random temp name: `<3 to 8 hex digits>.tmp` directly in a folder named `Temp` (`%TEMP%\6D5C.tmp`, what
/// `GetTempFileName` makes; m1b.sh's freeze normalises the same part, FZ_TEMP). Group 1 is the folder.
fn temp_name_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(.*\\temp)\\[0-9a-f]{3,8}\.tmp$").unwrap())
}

/// A log file directly in a folder named `logs` (`C:\Program Files (x86)\Steam\logs\service_log.txt`). Group 1 is
/// the folder.
fn log_dir_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(.*\\logs)\\[^\\]+\.(?:txt|log)$").unwrap())
}

/// Folder-level rules for paths a null run created (ruling 2026-11-18, M1b G3: dirty-base truth noise), each needing
/// a null run's item as its evidence, the folder kept literal (its own random tokens generalised as usual):
/// - a `%TEMP%`-style random temp name (`temp_name_re`) matches any other `<3 to 8 hex>.tmp` in the same `Temp`
///   folder, and what lies below it. Every dirty-base run, null runs too, leaves one (`6D5C.tmp`, `6194.tmp`); the
///   token rules leave a 4-digit hex name literal. Names with other letters (`DELEAE3.tmp`, `tem5A6A.tmp`,
///   `~nsuA.tmp`) are not covered: frozen truths hold such names as app leftovers.
/// - a new `.txt` / `.log` file directly in a folder named `logs` (`log_dir_re`) matches any new `.txt` / `.log`
///   file directly in that folder: a program running in the background (the Steam client that setup-dirty installs)
///   writes a different set of logs in each run. Narrow on purpose: a folder-level rule for every folder a null run
///   adds files to would also cover `%TEMP%` and `C:\Windows\Prefetch`, where every app leaves its own objects.
fn generalize_folder(kind: &str, body: &str, var: &GuidVariation) -> Option<String> {
    if kind != "P" {
        return None;
    }
    let folder = |dir: &str| generalize_body("P", dir, var).unwrap_or_else(|| regex::escape(dir));
    if let Some(c) = temp_name_re().captures(body) {
        return Some(format!(r"^P:{}\\[0-9a-f]{{3,8}}\.tmp(?:\\.*)?$", folder(&c[1])));
    }
    if let Some(c) = log_dir_re().captures(body) {
        return Some(format!(r"^P:{}\\[^\\]+\.(?:txt|log)$", folder(&c[1])));
    }
    None
}

/// Generalize a canonical target string: hex runs of 16+ and numbers of 6+ digits become typed wildcards, and a
/// GUID does too where `var` saw it vary (see `GuidVariation`); other GUIDs stay literal. A path that one of the
/// folder-level rules covers (`generalize_folder`) gets that rule instead. Returns an anchored regex
/// (case-insensitive use), or None if nothing was random. Path/key patterns also match descendants; value
/// patterns match `V:` and `C:` alike.
pub fn generalize(cs: &str, var: &GuidVariation) -> Option<String> {
    let (kind, body) = cs.split_once(':')?;
    if let Some(p) = generalize_folder(kind, body, var) {
        return Some(p);
    }
    let out = generalize_body(kind, body, var)?;
    let prefix = match kind {
        "V" | "C" => "[VC]:".to_string(),
        k => format!("{}:", regex::escape(k)),
    };
    let tail = match kind {
        "P" | "K" => r"(?:\\.*)?",
        _ => "",
    };
    Some(format!("^{prefix}{out}{tail}$"))
}

/// The escaped body of a canonical target string (after `kind:`) with its random tokens as wildcards (see
/// `generalize`), or None if nothing was random.
fn generalize_body(kind: &str, body: &str, var: &GuidVariation) -> Option<String> {
    let re = token_re();
    let mut out = String::new();
    let mut key = format!("{}:", kind_key(kind));
    let mut last = 0;
    let mut n = 0;
    for c in re.captures_iter(body) {
        let m = c.get(0).unwrap();
        let before = &body[last..m.start()];
        out.push_str(&regex::escape(before));
        key.push_str(&canon::fold(before));
        if c.name("guid").is_some() {
            let g = canon::fold(m.as_str().trim_start_matches('{').trim_end_matches('}'));
            if var.varies(&key) && !reg_root_re().is_match(&body[..m.start()]) {
                out.push_str(W_GUID);
                n += 1;
            } else {
                out.push_str(&regex::escape(m.as_str()));
            }
            key.push_str(&g);
        } else {
            let hex = c.name("hex").is_some();
            out.push_str(if hex { W_HEX } else { W_NUM });
            key.push_str(if hex { "\u{1}hex" } else { "\u{1}num" });
            n += 1;
        }
        last = m.end();
    }
    if n == 0 {
        return None;
    }
    out.push_str(&regex::escape(&body[last..]));
    Some(out)
}

/// One compiled ambient source (a run, or the union).
pub struct Matcher {
    pub id: String,
    exact: HashSet<String>,
    set: Option<RegexSet>,
    patterns: Vec<String>,
}

impl Matcher {
    pub fn new(id: &str, exact: &[String], patterns: &[String]) -> Result<Matcher> {
        let set = if patterns.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(patterns)
                    .case_insensitive(true)
                    .size_limit(1 << 28)
                    .dfa_size_limit(1 << 28)
                    .build()
                    .context("compile ambient patterns")?,
            )
        };
        Ok(Matcher {
            id: id.to_string(),
            exact: exact.iter().map(|s| canon::fold(s)).collect(),
            set,
            patterns: patterns.to_vec(),
        })
    }

    fn exact_hit(&self, s: &str) -> bool {
        self.exact.contains(&canon::fold(s))
    }

    /// Rule string if the (canonical) target is ambient.
    pub fn matches(&self, t: &Target) -> Option<String> {
        let cs = t.canon_string();
        let (kind, _) = cs.split_once(':').unwrap_or(("", ""));
        // exact, and descendants of an exact path/key
        if self.exact_hit(&cs) {
            return Some("ambient:exact".into());
        }
        match t {
            Target::Path { path } => {
                if canon::ancestors(path).any(|a| self.exact_hit(&format!("P:{a}"))) {
                    return Some("ambient:under-exact".into());
                }
            }
            Target::RegKey { path } => {
                if canon::ancestors(path).any(|a| self.exact_hit(&format!("K:{a}"))) {
                    return Some("ambient:under-exact".into());
                }
            }
            Target::RegValue { path, name } | Target::RegValueChanged { path, name, .. } => {
                let other = if kind == "V" { "C" } else { "V" };
                if self.exact_hit(&format!("{other}:{path}|{name}")) {
                    return Some("ambient:exact".into());
                }
                if std::iter::once(path.as_str())
                    .chain(canon::ancestors(path))
                    .any(|a| self.exact_hit(&format!("K:{a}")))
                {
                    return Some("ambient:under-exact".into());
                }
            }
            _ => {}
        }
        let set = self.set.as_ref()?;
        let mut hit = set.matches(&cs).into_iter().next();
        if hit.is_none()
            && let Target::RegValue { path, .. } | Target::RegValueChanged { path, .. } = t
        {
            hit = set.matches(&format!("K:{path}")).into_iter().next();
        }
        hit.map(|i| format!("ambient:pattern {}", self.patterns[i]))
    }
}

pub struct AmbientSet {
    pub union: Matcher,
    pub runs: Vec<Matcher>,
    /// An M2 ambient set (`purge.rig.m2ambient/1`, RIG.md §11.8): matched record by record (execdiff only).
    pub records: Option<RecordMatcher>,
}

impl AmbientSet {
    pub fn load(path: &Path) -> Result<AmbientSet> {
        let v: serde_json::Value = jsonio::read(path)?;
        if v.get("schema").and_then(serde_json::Value::as_str) == Some(M2_SCHEMA) {
            let j: M2AmbientJson =
                serde_json::from_value(v).with_context(|| format!("m2 ambient {}", path.display()))?;
            return Ok(AmbientSet {
                union: Matcher::new("union", &[], &[])?,
                runs: Vec::new(),
                records: Some(RecordMatcher::new(&j.records, &j.patterns)?),
            });
        }
        let j: AmbientJson = serde_json::from_value(v).with_context(|| format!("ambient {}", path.display()))?;
        let union = Matcher::new("union", &j.exact, &j.patterns)?;
        let runs = j.runs.iter().map(|r| Matcher::new(&r.id, &r.exact, &r.patterns)).collect::<Result<Vec<_>>>()?;
        Ok(AmbientSet { union, runs, records: None })
    }

    /// Is diff record `c` (as target `t`) ambient? An M2 set matches the record itself; an M0 / M1a set the target.
    pub fn matches_change(&self, c: &Change, t: &Target) -> Option<String> {
        match &self.records {
            Some(r) => r.matches(c),
            None => self.union.matches(t),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// M2 ambient set (RIG.md §11.8): diff records of the null runs' exec windows
// ---------------------------------------------------------------------------------------------

pub const M2_SCHEMA: &str = "purge.rig.m2ambient/1";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct M2AmbientRun {
    pub id: String,
    #[serde(default)]
    pub dir: String,
    /// The snapshot pair, `snap-<run>-a.tsv.gz` -> `snap-<run>-b.tsv.gz`.
    #[serde(default)]
    pub pair: Vec<String>,
    pub records: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct M2AmbientJson {
    pub schema: String,
    #[serde(default)]
    pub note: String,
    pub runs: Vec<M2AmbientRun>,
    /// Record keys `<op><rec>:<path>[|<value name>]` (op `-` or `~`), matched exactly (case-insensitive).
    pub records: Vec<String>,
    /// Anchored regexes over record keys: only GUID / hex / long-number tokens are wildcards, never a subtree.
    pub patterns: Vec<String>,
}

/// The record key of a diff record: `-F:C:\x`, `~K:HKLM\y`, `~V:HKLM\y|name`.
pub fn change_key(c: &Change) -> String {
    match c.rec {
        'V' => format!("{}V:{}|{}", c.op, c.path, c.name.as_deref().unwrap_or("")),
        r => format!("{}{}:{}", c.op, r, c.path),
    }
}

/// The target kind letter a record key's body generalises as (P for files and directories).
fn record_kind(rec: char) -> &'static str {
    match rec {
        'D' | 'F' => "P",
        'K' => "K",
        _ => "V",
    }
}

/// A record key as a canonical target string (`P:`, `K:`, `V:`), for the GUID variation.
fn record_as_target(key: &str) -> Option<String> {
    let mut ch = key.chars();
    let (_op, rec) = (ch.next()?, ch.next()?);
    let body = key.get(3..)?;
    Some(format!("{}:{body}", record_kind(rec)))
}

/// A record key with its random tokens as wildcards (`generalize` rules), anchored, matching that one record only:
/// no descendant tail, the op and record kind fixed. None if nothing was random.
pub fn generalize_record(key: &str, var: &GuidVariation) -> Option<String> {
    let mut ch = key.chars();
    let (op, rec) = (ch.next()?, ch.next()?);
    if key.get(2..3) != Some(":") {
        return None;
    }
    let body = generalize_body(record_kind(rec), key.get(3..)?, var)?;
    Some(format!("^{}{}:{body}$", regex::escape(&op.to_string()), regex::escape(&rec.to_string())))
}

pub struct RecordMatcher {
    exact: HashSet<String>,
    set: Option<RegexSet>,
    patterns: Vec<String>,
}

impl RecordMatcher {
    pub fn new(records: &[String], patterns: &[String]) -> Result<RecordMatcher> {
        let set = if patterns.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(patterns)
                    .case_insensitive(true)
                    .size_limit(1 << 28)
                    .dfa_size_limit(1 << 28)
                    .build()
                    .context("compile m2 ambient patterns")?,
            )
        };
        Ok(RecordMatcher { exact: records.iter().map(|s| canon::fold(s)).collect(), set, patterns: patterns.to_vec() })
    }

    pub fn matches(&self, c: &Change) -> Option<String> {
        let k = change_key(c);
        if self.exact.contains(&canon::fold(&k)) {
            return Some("m2-ambient:exact".into());
        }
        let i = self.set.as_ref()?.matches(&k).into_iter().next()?;
        Some(format!("m2-ambient:pattern {}", self.patterns[i]))
    }
}

/// The removed and changed records of one null run's exec window (rig records dropped). Added records are left out:
/// execdiff never fails on them (they are `unexplained`).
pub fn m2_run_records(a: &Snap, b: &Snap) -> Vec<String> {
    let rig = RigRules::new(&[a, b]);
    let mut out: Vec<String> = diff::diff(a, b)
        .iter()
        .filter(|c| c.op != '+')
        .filter(|c| {
            let k = change_key(c);
            record_as_target(&k).is_some_and(|t| rig.check(&t).is_none())
        })
        .map(change_key)
        .collect();
    out.sort_by(|x, y| canon::ci_cmp(x, y));
    out.dedup_by(|x, y| canon::ci_eq(x, y));
    out
}

/// `rigtool ambient --m2 --null DIR...`: each DIR a null run of an M2 mode (exec-run.ps1 with opts null), holding
/// `snap-<DIR name>-a.tsv.gz` and `-b.tsv.gz`.
pub fn cmd_ambient_m2(dirs: &[PathBuf], out: &Path) -> Result<()> {
    let mut items = Vec::new();
    for d in dirs {
        let id = d.file_name().and_then(|n| n.to_str()).unwrap_or("null").to_string();
        let fa = d.join(format!("snap-{id}-a.tsv.gz"));
        let fb = d.join(format!("snap-{id}-b.tsv.gz"));
        if !fa.is_file() || !fb.is_file() {
            crate::err::bail!(
                "{}: no snap-{id}-a.tsv.gz / snap-{id}-b.tsv.gz (a null run of an M2 mode?)",
                d.display()
            );
        }
        let a = Snap::load(&fa, LoadOpts::default())?;
        let b = Snap::load(&fb, LoadOpts::default())?;
        let recs = m2_run_records(&a, &b);
        items.push((id, d.display().to_string(), vec![fa.display().to_string(), fb.display().to_string()], recs));
    }
    let targets: Vec<String> =
        items.iter().flat_map(|(_, _, _, r)| r.iter().filter_map(|k| record_as_target(k))).collect();
    let var = GuidVariation::from_items(targets.iter());
    let mut runs = Vec::new();
    for (id, dir, pair, records) in items {
        let pats: BTreeSet<String> = records.iter().filter_map(|k| generalize_record(k, &var)).collect();
        eprintln!("ambient --m2: {id}: {} records, {} patterns", records.len(), pats.len());
        runs.push(M2AmbientRun { id, dir, pair, records, patterns: pats.into_iter().collect() });
    }
    let mut seen = HashSet::new();
    let mut records = Vec::new();
    for r in &runs {
        for k in &r.records {
            if seen.insert(canon::fold(k)) {
                records.push(k.clone());
            }
        }
    }
    records.sort_by(|a, b| canon::ci_cmp(a, b));
    let patterns: BTreeSet<String> = runs.iter().flat_map(|r| r.patterns.iter().cloned()).collect();
    let j = M2AmbientJson {
        schema: M2_SCHEMA.into(),
        note:
            "removed (-) and changed (~) records of diff(snap A, snap B) in null runs of the M2 modes (exec replaced \
               by an idle wait); a record is ambient only when it matches a key exactly or a token-generalised \
               pattern, never by a parent (vm/RIG.md section 11.8)"
                .into(),
        runs,
        records,
        patterns: patterns.into_iter().collect(),
    };
    eprintln!("ambient --m2: union {} records, {} patterns", j.records.len(), j.patterns.len());
    jsonio::write(out, &j)
}

/// Canonical strings of the churn in one null run (rig items dropped).
pub fn run_items(s0: &Snap, s2: &Snap) -> Vec<String> {
    let rig = RigRules::new(&[s0, s2]);
    items::derive(s0, s2).into_iter().map(|i| i.target.canon_string()).filter(|cs| rig.check(cs).is_none()).collect()
}

/// One run's ambient entries; `var` comes from all null runs of the campaign (`GuidVariation::from_items`).
pub fn build_run(id: &str, dir: &str, cs: Vec<String>, var: &GuidVariation) -> AmbientRunJson {
    let pats: BTreeSet<String> = cs.iter().filter_map(|c| generalize(c, var)).collect();
    AmbientRunJson { id: id.to_string(), dir: dir.to_string(), exact: cs, patterns: pats.into_iter().collect() }
}

pub fn union(runs: Vec<AmbientRunJson>) -> AmbientJson {
    let mut seen = HashSet::new();
    let mut exact = Vec::new();
    for r in &runs {
        for e in &r.exact {
            if seen.insert(canon::fold(e)) {
                exact.push(e.clone());
            }
        }
    }
    exact.sort_by(|a, b| canon::ci_cmp(a, b));
    let patterns: BTreeSet<String> = runs.iter().flat_map(|r| r.patterns.iter().cloned()).collect();
    AmbientJson { schema: "purge.rig.ambient/1".into(), runs, exact, patterns: patterns.into_iter().collect() }
}

pub fn cmd_ambient(dirs: &[PathBuf], out: &Path) -> Result<()> {
    let mut items = Vec::new();
    for d in dirs {
        let f0 = snap::find_phase_file(d, "snap", "0", ".tsv.gz")
            .with_context(|| format!("no snap-0 in {}", d.display()))?;
        let f2 = snap::find_phase_file(d, "snap", "2", ".tsv.gz")
            .with_context(|| format!("no snap-2 in {}", d.display()))?;
        let s0 = Snap::load(&f0, LoadOpts::default())?;
        let s2 = Snap::load(&f2, LoadOpts::default())?;
        items.push((d, run_items(&s0, &s2)));
    }
    // GUID wildcards are decided over all null runs together (a GUID that differs from run to run under the same
    // parent is random; one seen once is kept literal).
    let var = GuidVariation::from_items(items.iter().flat_map(|(_, cs)| cs.iter()));
    let mut runs = Vec::new();
    for (d, cs) in items {
        let id = d.file_name().and_then(|n| n.to_str()).unwrap_or("null").to_string();
        let r = build_run(&id, &d.display().to_string(), cs, &var);
        eprintln!("ambient: {id}: {} exact, {} patterns", r.exact.len(), r.patterns.len());
        runs.push(r);
    }
    let j = union(runs);
    eprintln!("ambient: union {} exact, {} patterns", j.exact.len(), j.patterns.len());
    jsonio::write(out, &j)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalization() {
        let p1 = "P:C:\\Users\\t\\AppData\\Local\\Temp\\{0A1B2C3D-0000-1111-2222-333344445555}".to_string();
        let p2 = "P:C:\\Users\\t\\AppData\\Local\\Temp\\{1A1B2C3D-0000-1111-2222-333344445555}\\x.log".to_string();
        let var = GuidVariation::from_items([&p1, &p2]);
        let g = generalize(&p1, &var).unwrap();
        let m = Matcher::new("x", &[], &[g]).unwrap();
        let t = |p: &str| Target::Path { path: p.into() };
        assert!(m.matches(&t("C:\\Users\\t\\AppData\\Local\\Temp\\{99999999-AAAA-bbbb-2222-333344445555}")).is_some());
        assert!(
            m.matches(&t("C:\\Users\\t\\AppData\\Local\\Temp\\{99999999-AAAA-bbbb-2222-333344445555}\\x.tmp"))
                .is_some()
        );
        assert!(m.matches(&t("C:\\Users\\t\\AppData\\Local\\Temp\\notaguid")).is_none());

        let h = generalize("K:HKLM\\SOFTWARE\\X\\cache-0123456789abcdef01", &var).unwrap();
        let m = Matcher::new("x", &[], &[h]).unwrap();
        assert!(m.matches(&Target::RegKey { path: "HKLM\\SOFTWARE\\X\\cache-FEDCBA98765432100A".into() }).is_some());
        assert!(m.matches(&Target::RegKey { path: "HKLM\\SOFTWARE\\X\\cache-FEDCBA9876".into() }).is_none());

        let n = generalize("V:HKU\\S\\Software\\Y|LastRun_20261111", &var).unwrap();
        let m = Matcher::new("x", &[], &[n]).unwrap();
        assert!(
            m.matches(&Target::RegValue { path: "HKU\\S\\Software\\Y".into(), name: "LastRun_20270101".into() })
                .is_some()
        );
        assert!(
            m.matches(&Target::RegValueChanged {
                path: "HKU\\S\\Software\\Y".into(),
                name: "LastRun_20270101".into(),
                before: String::new(),
                after: String::new()
            })
            .is_some()
        );
        assert!(
            m.matches(&Target::RegValue { path: "HKU\\S\\Software\\Y".into(), name: "LastRun_2027".into() }).is_none()
        );
        assert!(generalize("P:C:\\Program Files\\App\\app.exe", &var).is_none());
    }

    #[test]
    fn guid_wildcards_need_variation() {
        let k = |p: &str| Target::RegKey { path: p.into() };
        // r1-null1: two COM classes registered by Windows. Both stay literal: a GUID right under a registration
        // root is never a wildcard, so Firefox's own CLSID key is not ambient.
        let a = "K:HKLM\\SOFTWARE\\Classes\\CLSID\\{2F2CF653-0000-1111-2222-333344445555}".to_string();
        let b = "K:HKLM\\SOFTWARE\\Classes\\CLSID\\{883969F8-0000-1111-2222-333344445555}\\InProcServer32".to_string();
        let var = GuidVariation::from_items([&a, &b]);
        assert_eq!(generalize(&a, &var), None);
        assert_eq!(generalize(&b, &var), None);
        let ff = k("HKLM\\SOFTWARE\\Classes\\CLSID\\{1814CEEB-49E2-407F-AF99-FA755A7D2607}\\InProcServer32");
        let r = run_matcher(&[a.clone(), b.clone()], &var);
        assert!(r.matches(&ff).is_none());
        assert!(r.matches(&k("HKLM\\SOFTWARE\\Classes\\CLSID\\{2F2CF653-0000-1111-2222-333344445555}\\X")).is_some());
        for root in [
            "HKLM\\SOFTWARE\\Classes\\Interface\\",
            "HKLM\\SOFTWARE\\Classes\\AppID\\",
            "HKLM\\SOFTWARE\\Classes\\TypeLib\\",
            "HKLM\\SOFTWARE\\Classes\\WOW6432Node\\CLSID\\",
            "HKLM\\SOFTWARE\\WOW6432Node\\Classes\\CLSID\\",
            "HKU\\S-1-5-21-1-2-3-1000_Classes\\CLSID\\",
        ] {
            let x = format!("K:{root}{{00000000-0000-1111-2222-333344445555}}");
            let y = format!("K:{root}{{11111111-0000-1111-2222-333344445555}}");
            let var = GuidVariation::from_items([&x, &y]);
            assert_eq!(generalize(&x, &var), None, "{root}");
        }
        // One GUID seen once under a parent: literal (only the long number stays a wildcard).
        let one = "K:HKLM\\SOFTWARE\\Vendor\\{0A1B2C3D-0000-1111-2222-333344445555}\\T1234567".to_string();
        let var = GuidVariation::from_items([&one]);
        let r = run_matcher(std::slice::from_ref(&one), &var);
        assert!(r.matches(&k("HKLM\\SOFTWARE\\Vendor\\{0A1B2C3D-0000-1111-2222-333344445555}\\T7654321")).is_some());
        assert!(r.matches(&k("HKLM\\SOFTWARE\\Vendor\\{9A1B2C3D-0000-1111-2222-333344445555}\\T7654321")).is_none());
        // Varying GUIDs under a specific parent (different runs): wildcard, with the parent and kind fixed.
        let s1 = "K:HKLM\\SOFTWARE\\Microsoft\\Sched\\Tasks\\{0A1B2C3D-0000-1111-2222-333344445555}".to_string();
        let s2 = "K:HKLM\\SOFTWARE\\Microsoft\\Sched\\Tasks\\{0B1B2C3D-0000-1111-2222-333344445555}".to_string();
        let var = GuidVariation::from_items([&s1, &s2]);
        let r = run_matcher(std::slice::from_ref(&s1), &var);
        assert!(
            r.matches(&k("HKLM\\SOFTWARE\\Microsoft\\Sched\\Tasks\\{0C1B2C3D-0000-1111-2222-333344445555}\\Sub"))
                .is_some()
        );
        assert!(r.matches(&k("HKLM\\SOFTWARE\\Other\\Tasks\\{0C1B2C3D-0000-1111-2222-333344445555}")).is_none());
    }

    /// Ruling 2026-11-18 (M1b G3): the dirty-base null runs' `%TEMP%\<hex>.tmp` and Steam client logs cover the
    /// same churn in an app run, and nothing else: no other folder, no other name shape, no frozen app leftover.
    #[test]
    fn folder_rules_temp_names_and_log_folders() {
        let t = |p: &str| Target::Path { path: p.into() };
        let temp = "C:\\Users\\tester\\AppData\\Local\\Temp";
        let steam = "C:\\Program Files (x86)\\Steam\\logs";
        // m1bd-null1 / m1bd-null2 of the failed campaign
        let null = vec![format!("P:{temp}\\6D5C.tmp"), format!("P:{steam}\\appinfo_log.txt")];
        let var = GuidVariation::from_items(null.iter());
        let pats: Vec<String> = null.iter().filter_map(|c| generalize(c, &var)).collect();
        assert_eq!(pats.len(), 2, "{pats:?}");
        let m = Matcher::new("n", &null, &pats).unwrap();
        // the dirty temurin run's two "leftovers"
        assert!(m.matches(&t(&format!("{temp}\\6194.tmp"))).is_some());
        assert!(m.matches(&t(&format!("{steam}\\service_log.txt"))).is_some());
        // other temp-name lengths of the same shape (GetTempFileName: up to 4 hex digits; 3 to 8 allowed)
        assert!(m.matches(&t(&format!("{temp}\\abc.TMP"))).is_some());
        assert!(m.matches(&t(&format!("{temp}\\0123abcd.tmp\\x.dat"))).is_some());
        assert!(m.matches(&t(&format!("{temp}\\0123abcde.tmp"))).is_none());
        assert!(m.matches(&t(&format!("{temp}\\ab.tmp"))).is_none());
        // frozen app leftovers keep their label: other name shapes in %TEMP% (python, vcredist, npp, firefox, git)
        for leftover in
            ["DELEAE3.tmp", "DEL3917.tmp", "tem5A6A.tmp", "~nsuA.tmp", "is-TU8SYANY8F-uninstall.tmp", "6D5C.log"]
        {
            assert!(m.matches(&t(&format!("{temp}\\{leftover}"))).is_none(), "{leftover}");
        }
        // another folder named Temp is not covered by this folder's rule
        assert!(m.matches(&t("C:\\Windows\\Temp\\6194.tmp")).is_none());
        // the log rule: new .txt / .log files directly in that logs folder only
        assert!(m.matches(&t(&format!("{steam}\\webhelper.log"))).is_some());
        assert!(m.matches(&t(&format!("{steam}\\crash.dmp"))).is_none());
        assert!(m.matches(&t(&format!("{steam}\\sub\\x.txt"))).is_none());
        assert!(m.matches(&t(&format!("{steam}\\x.txt\\y"))).is_none());
        assert!(m.matches(&t("C:\\Program Files (x86)\\Steam\\service_log.txt")).is_none());
        assert!(m.matches(&t("C:\\Program Files\\App\\logs\\a.txt")).is_none());
        assert!(m.matches(&Target::RegKey { path: format!("HKLM\\SOFTWARE\\{steam}\\a.txt") }).is_none());
        // no evidence, no rule: a run without such items gives no folder pattern
        assert_eq!(generalize("P:C:\\Program Files\\App\\app.exe", &var), None);
        assert_eq!(generalize("P:C:\\Program Files\\App\\logs", &var), None);
        assert_eq!(generalize("K:HKLM\\SOFTWARE\\Temp\\6D5C.tmp", &var), None);
    }

    fn run_matcher(cs: &[String], var: &GuidVariation) -> Matcher {
        let pats: Vec<String> = cs.iter().filter_map(|c| generalize(c, var)).collect();
        Matcher::new("n", cs, &pats).unwrap()
    }

    fn ch(op: char, rec: char, path: &str, name: Option<&str>) -> Change {
        Change { op, rec, path: path.into(), name: name.map(str::to_string), changes: Vec::new() }
    }

    #[test]
    fn m2_records_match_one_record_never_a_subtree() {
        let recs = vec![
            "~K:HKU\\S-1-5-21-1336749127-99101324-1432799918-1000\\Software\\Microsoft".to_string(),
            "~F:C:\\Windows\\Prefetch\\SVCHOST.EXE-8BDB97E5.pf".to_string(),
            "-V:HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\X|134388838903517771".to_string(),
        ];
        let targets: Vec<String> = recs.iter().filter_map(|k| record_as_target(k)).collect();
        let var = GuidVariation::from_items(targets.iter());
        let pats: Vec<String> = recs.iter().filter_map(|k| generalize_record(k, &var)).collect();
        // The SID's long numbers and the value name's number are tokens; the prefetch name has none.
        assert_eq!(pats.len(), 2, "{pats:?}");
        let m = RecordMatcher::new(&recs, &pats).unwrap();
        // The key's own metadata change is ambient, in any user's hive ...
        assert!(
            m.matches(&ch('~', 'K', "HKU\\S-1-5-21-1336749127-99101324-1432799918-1000\\Software\\Microsoft", None))
                .is_some()
        );
        assert!(
            m.matches(&ch('~', 'K', "HKU\\S-1-5-21-2222222222-333333333-4444444444-1000\\Software\\Microsoft", None))
                .is_some()
        );
        // ... but never its removal, nor anything under it.
        assert!(
            m.matches(&ch('-', 'K', "HKU\\S-1-5-21-1336749127-99101324-1432799918-1000\\Software\\Microsoft", None))
                .is_none()
        );
        assert!(
            m.matches(&ch(
                '-',
                'K',
                "HKU\\S-1-5-21-1336749127-99101324-1432799918-1000\\Software\\Microsoft\\Office",
                None
            ))
            .is_none()
        );
        assert!(
            m.matches(&ch(
                '~',
                'V',
                "HKU\\S-1-5-21-1336749127-99101324-1432799918-1000\\Software\\Microsoft",
                Some("x")
            ))
            .is_none()
        );
        // A changed prefetch file: exact (case-insensitive); a removed one or a sibling is not.
        assert!(m.matches(&ch('~', 'F', "c:\\windows\\prefetch\\svchost.exe-8bdb97e5.PF", None)).is_some());
        assert!(m.matches(&ch('-', 'F', "C:\\Windows\\Prefetch\\SVCHOST.EXE-8BDB97E5.pf", None)).is_none());
        assert!(m.matches(&ch('~', 'F', "C:\\Windows\\Prefetch\\OTHER.EXE-8BDB97E5.pf", None)).is_none());
        // The removed value with another timestamp name: pattern; the key itself removed: not ambient.
        let k = "HKLM\\SOFTWARE\\Microsoft\\Wbem\\Tracing\\Providers\\X";
        assert!(m.matches(&ch('-', 'V', k, Some("134392558165883938"))).is_some());
        assert!(m.matches(&ch('-', 'K', k, None)).is_none());
        assert!(m.matches(&ch('-', 'V', k, Some("Other"))).is_none());
    }

    #[test]
    fn m2_set_loads_by_schema() {
        let dir = std::env::temp_dir().join(format!("rigtool-m2amb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m2-ambient.json");
        let j = M2AmbientJson {
            schema: M2_SCHEMA.into(),
            note: String::new(),
            runs: Vec::new(),
            records: vec!["~F:C:\\ProgramData\\Microsoft\\churn.log".into()],
            patterns: Vec::new(),
        };
        jsonio::write(&p, &j).unwrap();
        let s = AmbientSet::load(&p).unwrap();
        let c = ch('~', 'F', "C:\\ProgramData\\Microsoft\\churn.log", None);
        let t = Target::Path { path: c.path.clone() };
        assert!(s.matches_change(&c, &t).is_some());
        let d = ch('-', 'F', "C:\\ProgramData\\Microsoft\\churn.log", None);
        assert!(s.matches_change(&d, &t).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn exact_and_descendants() {
        let m = Matcher::new(
            "n1",
            &[
                "P:C:\\Windows\\Prefetch\\X.pf".into(),
                "K:HKLM\\SOFTWARE\\Churn".into(),
                "C:HKLM\\SOFTWARE\\A|Counter".into(),
            ],
            &[],
        )
        .unwrap();
        assert!(m.matches(&Target::Path { path: "c:\\windows\\prefetch\\x.PF".into() }).is_some());
        assert!(m.matches(&Target::RegKey { path: "HKLM\\SOFTWARE\\Churn\\Sub".into() }).is_some());
        assert!(m.matches(&Target::RegKey { path: "HKLM\\SOFTWARE\\Churned".into() }).is_none());
        assert!(m.matches(&Target::RegValue { path: "HKLM\\SOFTWARE\\Churn".into(), name: "v".into() }).is_some());
        assert!(m.matches(&Target::RegValue { path: "HKLM\\SOFTWARE\\A".into(), name: "Counter".into() }).is_some());
        assert!(m.matches(&Target::RegValue { path: "HKLM\\SOFTWARE\\A".into(), name: "Other".into() }).is_none());
    }
}
