//! `rigtool truth` (RIG.md §5): what the app really left behind, labelled.

use crate::ambient::AmbientSet;
use crate::canon::{self, CiStr, CiString, PrefixIndex};
use crate::deny::Deny;
use crate::err::{Context, Result, bail};
use crate::items::{self, Item, RigRules};
use crate::jsonio;
use crate::snap::{LoadOpts, Snap};
use crate::target::Target;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub const LABELS: [&str; 5] = ["rig", "ambient", "kept_owner", "user_data", "leftover"];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TruthItem {
    pub target: Target,
    pub label: String,
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lwt: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<bool>,
    /// Present after the install (snap-1) too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_s1: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TruthFile {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub run: Value,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub counts_by_kind: BTreeMap<String, BTreeMap<String, usize>>,
    #[serde(default)]
    pub ambient_by_run: BTreeMap<String, usize>,
    #[serde(default)]
    pub deny_hits: Vec<String>,
    #[serde(default)]
    pub snaps: Value,
    pub items: Vec<TruthItem>,
}

// ---------------------------------------------------------------------------------------------
// Label rules
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct LabelFileJson {
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    /// Other label files (relative to this one) whose rules come first, e.g. the shared `_os.json`.
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    rules: Vec<LabelRuleJson>,
}

#[derive(Deserialize)]
struct LabelRuleJson {
    label: String,
    #[serde(rename = "match")]
    pattern: String,
    #[serde(default)]
    why: String,
    /// The rule labels a container only: its new descendants are emitted as items of their own and
    /// labelled through the rule chain (RIG.md section 5).
    #[serde(default)]
    split: bool,
    /// Checked before the ambient set and the ambient rules (an app-attributable exception to them).
    #[serde(default)]
    first: bool,
}

pub struct LabelRule {
    pub label: String,
    pub re: Regex,
    pub why: String,
    pub split: bool,
    pub first: bool,
}

pub fn load_label_rules(path: &Path) -> Result<Vec<LabelRule>> {
    load_label_rules_depth(path, 0)
}

fn load_label_rules_depth(path: &Path, depth: usize) -> Result<Vec<LabelRule>> {
    if depth > 4 {
        bail!("{}: label includes nested too deeply", path.display());
    }
    let j: LabelFileJson = jsonio::read(path)?;
    let mut out = Vec::new();
    for inc in &j.include {
        let p = path.parent().unwrap_or(Path::new(".")).join(inc);
        out.extend(load_label_rules_depth(&p, depth + 1).with_context(|| format!("{}: include {inc:?}", path.display()))?);
    }
    for r in j.rules {
        if !LABELS.contains(&r.label.as_str()) {
            bail!("{}: unknown label {:?} (allowed: {:?})", path.display(), r.label, LABELS);
        }
        let re = RegexBuilder::new(&r.pattern)
            .case_insensitive(true)
            .build()
            .with_context(|| format!("{}: bad regex {:?}", path.display(), r.pattern))?;
        out.push(LabelRule { label: r.label, re, why: r.why, split: r.split, first: r.first });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// kept_owner anchors from ARP entries still installed after the uninstall
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
pub struct KeptAnchors {
    paths: PrefixIndex<String>,
    keys: PrefixIndex<String>,
    pub described: Vec<String>,
}

/// MSI packed GUID: {12345678-9ABC-DEF0-1234-56789ABCDEF0} -> 87654321CBA90FED2143658709BADCFE.
pub fn packed_guid(g: &str) -> Option<String> {
    let h: String = g.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if h.len() != 32 {
        return None;
    }
    let rev = |s: &str| s.chars().rev().collect::<String>();
    let mut o = String::new();
    o.push_str(&rev(&h[0..8]));
    o.push_str(&rev(&h[8..12]));
    o.push_str(&rev(&h[12..16]));
    for i in (16..32).step_by(2) {
        o.push_str(&rev(&h[i..i + 2]));
    }
    Some(o.to_ascii_uppercase())
}

fn broad_dir(p: &str) -> bool {
    let f = canon::fold(p);
    static BROAD: &[&str] = &[
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\program files\\common files",
        "c:\\program files (x86)\\common files",
        "c:\\programdata",
        "c:\\users",
        "c:\\users\\public",
        "c:\\windows",
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
    ];
    if f.len() <= 3 || BROAD.contains(&f.as_str()) {
        return true;
    }
    let re = Regex::new(r"^[a-z]:\\users\\[^\\]+(\\appdata(\\(local|roaming|locallow)(\\programs)?)?)?$").unwrap();
    re.is_match(&f)
}

/// Executable path at the start of a command line or icon spec.
fn exe_of(s: &str) -> Option<String> {
    let t = s.trim();
    let t = if let Some(r) = t.strip_prefix('"') { r.split('"').next().unwrap_or("") } else { t };
    let lower = t.to_ascii_lowercase();
    let end = lower.find(".exe").map(|i| i + 4).unwrap_or_else(|| lower.find(',').unwrap_or(lower.len()));
    let p = t[..end].trim();
    if p.len() < 4 || !p.as_bytes().get(1).is_some_and(|b| *b == b':') {
        return None;
    }
    if p.to_ascii_lowercase().ends_with("msiexec.exe") {
        return None;
    }
    Some(canon::canon_path(p))
}

fn uninstall_list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o.get("uninstall").and_then(|x| x.as_array()).cloned().unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string).filter(|x| !x.trim().is_empty())
}

/// ARP entries created by the install and still present after the uninstall.
pub fn kept_entries(run: &Value, lists0: &Value, lists2: &Value, sid: Option<&str>) -> Vec<Value> {
    let l0 = uninstall_list(lists0);
    let l2 = uninstall_list(lists2);
    let key_of = |e: &Value| s(e, "key").map(|k| canon::fold(&canon::canon_reg(&k, sid)));
    let in0: HashSet<String> = l0.iter().filter_map(key_of).collect();
    let mut out: Vec<Value> = Vec::new();
    let mut seen = HashSet::new();
    let find2 = |k: &str| l2.iter().find(|e| key_of(e).as_deref() == Some(k)).cloned();
    if let Some(Value::Array(left)) = run.get("entries_left") {
        for e in left {
            let (k, obj) = match e {
                Value::String(k) => (canon::fold(&canon::canon_reg(k, sid)), json!({ "key": k })),
                Value::Object(_) => match key_of(e) {
                    Some(k) => (k, e.clone()),
                    None => continue,
                },
                _ => continue,
            };
            if seen.insert(k.clone()) {
                out.push(find2(&k).unwrap_or(obj));
            }
        }
    }
    // "Created by the install" needs the clean list: without lists-0 every preinstalled product in
    // lists-2 would look new and become a kept_owner anchor.
    if lists0.is_null() {
        if !l2.is_empty() {
            eprintln!("truth: warning: no lists-0; skipping the lists-2 minus lists-0 kept_owner rule");
        }
        return out;
    }
    for e in &l2 {
        if let Some(k) = key_of(e)
            && !in0.contains(&k)
            && seen.insert(k)
        {
            out.push(e.clone());
        }
    }
    out
}

/// Microsoft Store self-updates between lists-0 and lists-2: non-sparse packages installed under
/// `C:\Program Files\WindowsApps`, published by Microsoft (publisher id `8wekyb3d8bbwe`), whose full name is in
/// exactly one of the two lists (an inbox app replaced by a newer version, or a framework it pulled in). No
/// desktop installer of the corpus deploys such a package (the apps' own packages are sparse), so what names
/// them is OS-owned by construction (2026-11-15, x2 review: Photos, VCLibs and OneDrive.Photos updated
/// themselves inside 9 of 16 runs). Returns (folded needle, family) pairs: each full name and its family.
pub fn store_updates(lists0: &Value, lists2: &Value) -> Vec<(String, String)> {
    let appx = |v: &Value| -> Vec<Value> { v.get("appx").and_then(|x| x.as_array()).cloned().unwrap_or_default() };
    let (a0, a2) = (appx(lists0), appx(lists2));
    if lists0.is_null() || lists2.is_null() {
        return Vec::new();
    }
    let names = |a: &[Value]| -> HashSet<String> { a.iter().filter_map(|e| s(e, "full_name")).map(|n| canon::fold(&n)).collect() };
    let (n0, n2) = (names(&a0), names(&a2));
    let mut out: Vec<(String, String)> = Vec::new();
    for e in a0.iter().chain(a2.iter()) {
        let Some(full) = s(e, "full_name") else { continue };
        let f = canon::fold(&full);
        if n0.contains(&f) == n2.contains(&f) {
            continue;
        }
        let sparse = e.get("sparse").and_then(|x| x.as_bool()).unwrap_or(true);
        let loc = s(e, "install_location").map(|l| canon::fold(&l)).unwrap_or_default();
        let Some(family) = crate::score::package_family(&full) else { continue };
        if sparse || !loc.starts_with(&canon::fold("C:\\Program Files\\WindowsApps\\")) || !canon::fold(&family).ends_with("_8wekyb3d8bbwe") {
            continue;
        }
        for n in [f, canon::fold(&family)] {
            if !out.iter().any(|(x, _)| *x == n) {
                out.push((n, family.clone()));
            }
        }
    }
    out
}

/// Relabel the `leftover` / `user_data` items that name a Store self-updated package (see [`store_updates`]) as
/// `ambient`. Returns how many were relabelled.
pub fn relabel_store_updates(items: &mut [TruthItem], upd: &[(String, String)]) -> usize {
    if upd.is_empty() {
        return 0;
    }
    let mut n = 0;
    for i in items.iter_mut().filter(|i| i.label == "leftover" || i.label == "user_data") {
        let cs = canon::fold(&i.target.canon_string());
        if let Some((_, fam)) = upd.iter().find(|(x, _)| cs.contains(x.as_str())) {
            i.label = "ambient".into();
            i.rule = format!("built-in: Microsoft Store self-update of {fam} (full name differs between lists-0 and lists-2)");
            n += 1;
        }
    }
    n
}

impl KeptAnchors {
    pub fn from_entries(entries: &[Value], sid: Option<&str>) -> KeptAnchors {
        let mut p: Vec<(String, String)> = Vec::new();
        let mut k: Vec<(String, String)> = Vec::new();
        let mut described = Vec::new();
        for e in entries {
            let Some(key) = s(e, "key") else { continue };
            let key = canon::canon_reg(&key, sid);
            let name = s(e, "name").unwrap_or_else(|| key.rsplit('\\').next().unwrap_or("").to_string());
            let why = format!("entries_left: {name}");
            described.push(format!("{name} [{key}]"));
            k.push((key.clone(), why.clone()));
            if let Some(loc) = s(e, "loc") {
                let l = canon::canon_path(loc.trim_matches('"'));
                if !broad_dir(&l) {
                    p.push((l, why.clone()));
                }
            }
            for f in ["icon", "uninstall", "quiet"] {
                if let Some(x) = s(e, f).and_then(|c| exe_of(&c)) {
                    p.push((x, why.clone()));
                }
            }
            if let Some(msi) = s(e, "msi").and_then(|g| packed_guid(&g).map(|pk| (g, pk))) {
                let (g, pk) = msi;
                let mut ks = vec![
                    format!("HKLM\\SOFTWARE\\Classes\\Installer\\Products\\{pk}"),
                    format!("HKLM\\SOFTWARE\\Classes\\Installer\\Features\\{pk}"),
                    format!("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\{pk}"),
                    format!("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}", g.trim()),
                ];
                if let Some(sid) = sid {
                    ks.push(format!("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\{sid}\\Products\\{pk}"));
                    ks.push(format!("HKU\\{sid}\\Software\\Microsoft\\Installer\\Products\\{pk}"));
                    ks.push(format!("HKU\\{sid}\\Software\\Microsoft\\Installer\\Features\\{pk}"));
                }
                for x in ks {
                    k.push((x, why.clone()));
                }
            }
        }
        KeptAnchors { paths: PrefixIndex::new(p), keys: PrefixIndex::new(k), described }
    }

    pub fn check(&self, t: &Target) -> Option<String> {
        let hits = match t {
            Target::Path { path } => self.paths.ancestors_or_eq(path),
            Target::RegKey { path } | Target::RegValue { path, .. } | Target::RegValueChanged { path, .. } => {
                self.keys.ancestors_or_eq(path)
            }
            _ => Vec::new(),
        };
        hits.into_iter().next()
    }
}

// ---------------------------------------------------------------------------------------------
// Labeler
// ---------------------------------------------------------------------------------------------

pub struct Labeler {
    pub rig: RigRules,
    pub ambient: Option<AmbientSet>,
    pub rules: Vec<LabelRule>,
    pub kept: KeptAnchors,
}

impl Labeler {
    fn rule_for(&self, label: &str, cs: &str) -> Option<String> {
        self.rules.iter().find(|r| r.label == label && r.re.is_match(cs)).map(|r| {
            if r.why.is_empty() { format!("labels: {}", r.re.as_str()) } else { format!("labels: {}", r.why) }
        })
    }

    /// (label, rule). First match wins: rig, ambient set, ambient rules, kept_owner rules,
    /// entries_left, user_data rules, leftover rules, default leftover.
    pub fn label(&self, t: &Target) -> (String, String) {
        let cs = t.canon_string();
        if let Some(r) = self.rig.check(&cs) {
            return ("rig".into(), r.to_string());
        }
        if let Some(r) = self.rule_for("rig", &cs) {
            return ("rig".into(), r);
        }
        if let Some(r) = self.rules.iter().find(|r| r.first && r.re.is_match(&cs)) {
            let why = if r.why.is_empty() { format!("labels: {}", r.re.as_str()) } else { format!("labels: {}", r.why) };
            return (r.label.clone(), why);
        }
        if let Target::RegValueChanged { before, after, .. } = t
            && same_segments(before, after)
        {
            return (
                "ambient".into(),
                "built-in: list value with the same segments before and after (only empty segments or separators differ)".into(),
            );
        }
        if let Some(a) = &self.ambient
            && let Some(r) = a.union.matches(t)
        {
            return ("ambient".into(), r);
        }
        if let Some(r) = self.rule_for("ambient", &cs) {
            return ("ambient".into(), r);
        }
        if let Some(r) = self.rule_for("kept_owner", &cs) {
            return ("kept_owner".into(), r);
        }
        if let Some(r) = self.kept.check(t) {
            return ("kept_owner".into(), r);
        }
        if let Some(r) = self.rule_for("user_data", &cs) {
            return ("user_data".into(), r);
        }
        if let Some(r) = self.rule_for("leftover", &cs) {
            return ("leftover".into(), r);
        }
        ("leftover".into(), "default".into())
    }

    /// Is `t` labelled by a `split` rule (a container whose new descendants become items of their own)?
    pub fn split_rule(&self, t: &Target) -> bool {
        let (l, why) = self.label(t);
        if l != "ambient" {
            return false;
        }
        let cs = t.canon_string();
        self.rules
            .iter()
            .find(|r| r.label == "ambient" && r.re.is_match(&cs))
            .is_some_and(|r| r.split && why == format!("labels: {}", if r.why.is_empty() { r.re.as_str() } else { r.why.as_str() }))
    }

    /// Would `t` belong to a still-installed product (a kept_owner rule or an entries_left anchor)?
    pub fn kept_reason(&self, t: &Target) -> Option<String> {
        self.rule_for("kept_owner", &t.canon_string()).or_else(|| self.kept.check(t))
    }
}

/// `;`-separated list values (PATH, PSModulePath, PATHEXT) whose non-empty segments are the same, in the
/// same order, compared case-insensitively and ignoring a trailing `\`. A `#hash` stand-in or a preview cut
/// at PREVIEW_MAX is never treated as equal.
pub fn same_segments(before: &str, after: &str) -> bool {
    // A list is recognised by a `;` on either side: an uninstaller that removes its segment can leave a
    // one-segment list without one (`X;` -> `X`).
    let complete = |s: &str| !s.starts_with('#') && s.chars().count() < crate::snap::PREVIEW_MAX;
    if !complete(before) || !complete(after) || !(before.contains(';') || after.contains(';')) {
        return false;
    }
    let seg = |s: &str| -> Vec<String> {
        s.split(';').map(str::trim).filter(|x| !x.is_empty()).map(|x| canon::fold(x.trim_end_matches('\\'))).collect()
    };
    seg(before) == seg(after)
}

// ---------------------------------------------------------------------------------------------
// Opening containers labelled by `split` rules
// ---------------------------------------------------------------------------------------------

/// `derive` collapses a new subtree into its top-most key or dir. When a `split` rule labels that top as a
/// Windows container (e.g. `Classes\PackagedCom`, `Explorer\FeatureUsage`), what an app put inside must
/// still be judged on its own: emit the container's new direct children (keys, values, dirs, files) as
/// items, recursively while a child is itself a `split` container. Returns the items and the number of
/// containers opened.
pub fn split_containers(items: Vec<Item>, s2: &Snap, lab: &Labeler) -> (Vec<Item>, usize) {
    let mut out = Vec::with_capacity(items.len());
    let mut work = items;
    let mut n = 0;
    while let Some(it) = work.pop() {
        let is_dir = it.dir == Some(true);
        let is_key = matches!(it.target, Target::RegKey { .. });
        if (is_dir || is_key) && lab.split_rule(&it.target) {
            n += 1;
            let top = it.target.path().to_string();
            let is_child = |p: &str| canon::parent(p).is_some_and(|q| canon::ci_eq(q, &top));
            if is_key {
                if let Some(r) = s2.key(&top) {
                    for v in &r.values {
                        work.push(Item {
                            target: Target::RegValue { path: top.clone(), name: v.name.clone() },
                            size: Some(v.len as u64),
                            lwt: Some(r.lwt),
                            dir: None,
                        });
                    }
                }
                for (k, r) in &s2.keys {
                    if r.seen && is_child(k.as_str()) {
                        work.push(Item { target: Target::RegKey { path: k.0.clone() }, size: None, lwt: Some(r.lwt), dir: None });
                    }
                }
            } else {
                for (p, r) in &s2.fs {
                    if !is_child(p.as_str()) {
                        continue;
                    }
                    let size = if r.dir {
                        s2.fs
                            .iter()
                            .filter(|(q, f)| !f.dir && canon::is_under_or_eq(q.as_str(), p.as_str()))
                            .map(|(_, f)| f.size)
                            .sum()
                    } else {
                        r.size
                    };
                    work.push(Item { target: Target::Path { path: p.0.clone() }, size: Some(size), lwt: Some(r.mtime), dir: Some(r.dir) });
                }
            }
        }
        out.push(it);
    }
    items::sort_items(&mut out);
    (out, n)
}

// ---------------------------------------------------------------------------------------------
// Splitting collapsed items at kept_owner boundaries
// ---------------------------------------------------------------------------------------------

/// `derive` collapses a new subtree into its top-most key or dir. When that subtree also holds something a
/// still-installed product owns (an entries_left anchor or a kept_owner rule match below the top), the
/// single item would be labelled `leftover` and deleting it would score as a hit. Split such an item: emit
/// each kept subtree as its own item (labelled kept_owner later), every other child along the way as its
/// own item, and the values of the container keys on the path; the container itself is not an item (an
/// offer of it covers a kept_owner item, so it scores as danger). Returns the new items and how many
/// collapsed items were split.
///
/// The same split happens at `user_data` boundaries below a top labelled `leftover` (x0 runs, RIG.md §5): a
/// user file planted inside a new install root (`plant_post`) is matched by a `user_data` rule of the variant's
/// label file, so it becomes its own `user_data` item instead of disappearing into the root's single
/// `leftover` item; an offer of the root then covers it (`userdata_preselected`). A top that is itself
/// `user_data` is never split this way.
pub fn split_kept(items: Vec<Item>, s0: &Snap, s2: &Snap, lab: &Labeler) -> (Vec<Item>, usize) {
    // Candidates: collapsed dirs and keys that would be labelled leftover or user_data.
    let mut ptop: HashMap<CiString, usize> = HashMap::new();
    let mut ktop: HashMap<CiString, usize> = HashMap::new();
    let mut top_leftover: HashSet<usize> = HashSet::new();
    for (i, it) in items.iter().enumerate() {
        let is_dir = it.dir == Some(true);
        let is_key = matches!(it.target, Target::RegKey { .. });
        if !is_dir && !is_key {
            continue;
        }
        let (l, _) = lab.label(&it.target);
        if l != "leftover" && l != "user_data" {
            continue;
        }
        if l == "leftover" {
            top_leftover.insert(i);
        }
        let m = if is_key { &mut ktop } else { &mut ptop };
        m.insert(CiString(it.target.path().to_string()), i);
    }
    if ptop.is_empty() && ktop.is_empty() {
        return (items, 0);
    }

    // Descendants (strictly below) of each candidate: the new entries whose top-most new ancestor it is.
    let mut desc: HashMap<usize, Vec<String>> = HashMap::new();
    if !ptop.is_empty() {
        for p in s2.fs.keys() {
            if s0.has_path(p.as_str()) {
                continue;
            }
            for a in canon::ancestors(p.as_str()) {
                if let Some(&i) = ptop.get(CiStr::new(a)) {
                    desc.entry(i).or_default().push(p.0.clone());
                    break;
                }
                if !s2.has_path(a) || s0.has_path(a) {
                    break;
                }
            }
        }
    }
    if !ktop.is_empty() {
        for (k, r) in &s2.keys {
            if !r.seen || s0.has_key(k.as_str()) {
                continue;
            }
            for a in canon::ancestors(k.as_str()) {
                if let Some(&i) = ktop.get(CiStr::new(a)) {
                    desc.entry(i).or_default().push(k.0.clone());
                    break;
                }
                if !s2.has_key(a) || s0.has_key(a) {
                    break;
                }
            }
        }
    }

    let mut replaced: HashMap<usize, Vec<Item>> = HashMap::new();
    for (&i, d) in &desc {
        let top = items[i].target.path().to_string();
        let is_key = matches!(items[i].target, Target::RegKey { .. });
        let mk = |p: &str| if is_key { Target::RegKey { path: p.to_string() } } else { Target::Path { path: p.to_string() } };
        // Kept entries (and, below a leftover top, user_data entries) below the top, reduced to the top-most ones.
        let user_split = top_leftover.contains(&i);
        let marked: HashSet<String> = d
            .iter()
            .filter(|p| {
                let t = mk(p);
                lab.kept_reason(&t).is_some()
                    || (user_split
                        && lab.rule_for("user_data", &t.canon_string()).is_some()
                        && lab.label(&t).0 == "user_data")
            })
            .map(|p| canon::fold(p))
            .collect();
        if marked.is_empty() {
            continue;
        }
        let minimal: Vec<&String> =
            d.iter().filter(|p| marked.contains(&canon::fold(p)) && !canon::ancestors(p).any(|a| marked.contains(&canon::fold(a)))).collect();
        // Containers: the top and every ancestor of a kept entry below it (folded -> original case).
        let ftop = canon::fold(&top);
        let mut cont: HashMap<String, String> = HashMap::new();
        cont.insert(ftop.clone(), top.clone());
        for m in &minimal {
            for a in canon::ancestors(m) {
                let fa = canon::fold(a);
                if fa.len() <= ftop.len() {
                    break;
                }
                cont.insert(fa, a.to_string());
            }
        }
        let mut out: Vec<Item> = Vec::new();
        let mut emitted: HashMap<String, usize> = HashMap::new();
        for p in d {
            let fp = canon::fold(p);
            if cont.contains_key(&fp) {
                continue;
            }
            let Some(parent) = canon::parent(p) else { continue };
            if !cont.contains_key(&canon::fold(parent)) {
                continue;
            }
            if is_key {
                let lwt = s2.key(p).map(|r| r.lwt);
                out.push(Item { target: mk(p), size: None, lwt, dir: None });
            } else {
                let r = s2.path(p);
                let dir = r.map(|r| r.dir);
                let size = r.filter(|r| !r.dir).map(|r| r.size).unwrap_or(0);
                out.push(Item { target: mk(p), size: Some(size), lwt: r.map(|r| r.mtime), dir });
            }
            emitted.insert(fp, out.len() - 1);
        }
        if is_key {
            // Values of the container keys are leftovers of their own now.
            let mut cs: Vec<&String> = cont.values().collect();
            cs.sort();
            for c in cs {
                if let Some(r) = s2.key(c) {
                    for v in &r.values {
                        out.push(Item {
                            target: Target::RegValue { path: c.clone(), name: v.name.clone() },
                            size: Some(v.len as u64),
                            lwt: Some(r.lwt),
                            dir: None,
                        });
                    }
                }
            }
        } else {
            // Sizes of the emitted dirs.
            for p in d {
                let Some(r) = s2.path(p).filter(|r| !r.dir) else { continue };
                if let Some(&j) = canon::ancestors(p).find_map(|a| emitted.get(&canon::fold(a)))
                    && let Some(s) = out[j].size.as_mut()
                {
                    *s += r.size;
                }
            }
        }
        replaced.insert(i, out);
    }
    let n_split = replaced.len();
    if n_split == 0 {
        return (items, 0);
    }
    let mut res = Vec::with_capacity(items.len());
    for (i, it) in items.into_iter().enumerate() {
        match replaced.remove(&i) {
            Some(v) => res.extend(v),
            None => res.push(it),
        }
    }
    items::sort_items(&mut res);
    (res, n_split)
}

fn in_snap(s: &Snap, t: &Target) -> bool {
    match t {
        Target::Path { path } => s.has_path(path),
        Target::RegKey { path } => s.has_key(path),
        Target::RegValue { path, name } | Target::RegValueChanged { path, name, .. } => s.value(path, name).is_some(),
        _ => false,
    }
}

/// Label derived items. Pure (no IO) so it can be unit-tested.
pub fn label_items(items: Vec<Item>, lab: &Labeler, s1: Option<&Snap>) -> Vec<TruthItem> {
    items
        .into_iter()
        .map(|i| {
            let (label, rule) = lab.label(&i.target);
            let in_s1 = s1.map(|s| in_snap(s, &i.target));
            TruthItem { target: i.target, label, rule, size: i.size, lwt: i.lwt, dir: i.dir, in_s1 }
        })
        .collect()
}

pub fn summarize(id: &str, items: Vec<TruthItem>) -> TruthFile {
    let mut counts: BTreeMap<String, usize> = LABELS.iter().map(|l| (l.to_string(), 0)).collect();
    let mut by_kind: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for i in &items {
        *counts.entry(i.label.clone()).or_default() += 1;
        *by_kind.entry(i.target.kind().to_string()).or_default().entry(i.label.clone()).or_default() += 1;
    }
    TruthFile {
        schema: "purge.rig.truth/1".into(),
        id: id.to_string(),
        counts,
        counts_by_kind: by_kind,
        items,
        ..Default::default()
    }
}

pub struct TruthArgs {
    pub s0: PathBuf,
    pub s1: Option<PathBuf>,
    pub s2: PathBuf,
    pub lists0: Option<PathBuf>,
    pub lists2: Option<PathBuf>,
    pub run: Option<PathBuf>,
    pub ambient: Option<PathBuf>,
    /// Label files, in order (repeatable `--labels`): their rules are concatenated. A label's precedence
    /// comes from the label order (RIG.md section 5), not from the file order.
    pub labels: Vec<PathBuf>,
    pub deny: Option<PathBuf>,
    pub sid: Option<String>,
    pub out: PathBuf,
}

pub fn cmd_truth(a: &TruthArgs) -> Result<()> {
    let s0 = Snap::load(&a.s0, LoadOpts::default())?;
    let s2 = Snap::load(&a.s2, LoadOpts::default())?;
    let s1 = match &a.s1 {
        Some(p) => Some(Snap::load(p, LoadOpts { values: true, previews: false })?),
        None => None,
    };
    let run: Value = match &a.run {
        Some(p) => jsonio::read(p)?,
        None => json!({}),
    };
    let lists0: Value = match &a.lists0 {
        Some(p) => jsonio::read(p)?,
        None => Value::Null,
    };
    let lists2: Value = match &a.lists2 {
        Some(p) => jsonio::read(p)?,
        None => Value::Null,
    };
    let sid = a
        .sid
        .clone()
        .or_else(|| run.get("sid").and_then(|x| x.as_str()).map(str::to_string))
        .or_else(|| s0.guess_user_sid());
    let id = run
        .get("id")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .or_else(|| a.out.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).map(str::to_string))
        .unwrap_or_default();

    let ambient = match &a.ambient {
        Some(p) => Some(AmbientSet::load(p)?),
        None => None,
    };
    let mut rules = Vec::new();
    for p in &a.labels {
        rules.extend(load_label_rules(p)?);
    }
    let entries = kept_entries(&run, &lists0, &lists2, sid.as_deref());
    let kept = KeptAnchors::from_entries(&entries, sid.as_deref());
    let lab = Labeler { rig: RigRules::new(&[&s0, &s2]), ambient, rules, kept };

    let (opened, n_open) = split_containers(items::derive(&s0, &s2), &s2, &lab);
    if n_open > 0 {
        eprintln!("truth: opened {n_open} container item(s) labelled by split rules");
    }
    let (derived, n_split) = split_kept(opened, &s0, &s2, &lab);
    let n_derived = derived.len();
    if n_split > 0 {
        eprintln!("truth: split {n_split} collapsed item(s) at kept_owner / user_data boundaries");
    }
    if s0.alias_dropped + s2.alias_dropped > 0 {
        eprintln!(
            "truth: dropped {} records below HKU\\S-1-5-18 (a followed link to HKU\\.DEFAULT in an older snap)",
            s0.alias_dropped + s2.alias_dropped
        );
    }
    let mut items = label_items(derived, &lab, s1.as_ref());
    let upd = store_updates(&lists0, &lists2);
    let n_store = relabel_store_updates(&mut items, &upd);
    if n_store > 0 {
        let fams: BTreeSet<&str> = upd.iter().map(|(_, f)| f.as_str()).collect();
        eprintln!(
            "truth: {n_store} item(s) of Store self-updated packages labelled ambient ({})",
            fams.into_iter().collect::<Vec<_>>().join(", ")
        );
    }

    let mut tf = summarize(&id, items);
    tf.run = run;
    tf.sid = sid.clone();
    tf.snaps = json!({
        "s0": {"file": a.s0.display().to_string(), "header": s0.header, "errors": s0.errors},
        "s1": a.s1.as_ref().map(|p| p.display().to_string()),
        "s2": {"file": a.s2.display().to_string(), "header": s2.header, "errors": s2.errors},
        "kept_entries": lab.kept.described,
    });
    if let Some(amb) = &lab.ambient {
        for r in &amb.runs {
            let n = tf.items.iter().filter(|i| i.label != "rig" && r.matches(&i.target).is_some()).count();
            tf.ambient_by_run.insert(r.id.clone(), n);
        }
    }
    if let Some(d) = &a.deny {
        let deny = Deny::load(d, sid.as_deref())?;
        tf.deny_hits = tf
            .items
            .iter()
            .filter(|i| i.label == "leftover" || i.label == "user_data")
            .filter_map(|i| deny.check(&i.target).map(|w| format!("{} ({w})", i.target.canon_string())))
            .collect();
    }
    jsonio::write(&a.out, &tf)?;
    eprintln!(
        "truth: {id}: {n_derived} items; {}",
        tf.counts.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" ")
    );
    if !tf.ambient_by_run.is_empty() {
        eprintln!(
            "truth: ambient removed per null run: {}",
            tf.ambient_by_run.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" ")
        );
    }
    // One line per hit up to 10, then a count (the full list is in the truth file's `deny_hits`).
    for h in tf.deny_hits.iter().take(10) {
        eprintln!("truth: warning: leftover matches deny: {h}");
    }
    if tf.deny_hits.len() > 10 {
        eprintln!("truth: warning: {} more leftover item(s) match the deny list (deny_hits in {})", tf.deny_hits.len() - 10, a.out.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ambient::Matcher;
    use crate::snap::{write_d, write_f, write_k, write_v};
    use crate::testutil::snap_text;

    fn rule(label: &str, re: &str) -> LabelRule {
        LabelRule {
            label: label.into(),
            re: RegexBuilder::new(re).case_insensitive(true).build().unwrap(),
            why: String::new(),
            split: false,
            first: false,
        }
    }

    #[test]
    fn packed() {
        assert_eq!(packed_guid("{12345678-9ABC-DEF0-1234-56789ABCDEF0}").unwrap(), "87654321CBA90FED21436587A9CBED0F");
    }

    #[test]
    fn label_precedence() {
        let sid = "S-1-5-21-1-1-1-1001";
        let entries = vec![json!({
            "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "name": "Py Launcher", "loc": "C:\\Program Files\\PyLauncher\\", "icon": "C:\\Windows\\py.exe,0",
            "msi": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        })];
        let kept = KeptAnchors::from_entries(&entries, Some(sid));
        let amb = AmbientSet {
            union: Matcher::new("u", &["P:C:\\Windows\\Prefetch\\X.pf".into(), "P:C:\\cr\\out".into()], &[]).unwrap(),
            runs: vec![],
        };
        let lab = Labeler {
            rig: RigRules::new(&[]),
            ambient: Some(amb),
            rules: vec![
                rule("user_data", r"^P:C:\\Users\\[^\\]+\\AppData\\Roaming\\App\\Profiles"),
                rule("ambient", r"^P:C:\\Windows\\Logs\\"),
                rule("kept_owner", r"^K:HKLM\\SOFTWARE\\Python\\PyLauncher"),
                // A user_data rule that also matches an ambient item: ambient must win.
                rule("user_data", r"Prefetch"),
            ],
            kept,
        };
        let p = |s: &str| Target::Path { path: s.into() };
        let k = |s: &str| Target::RegKey { path: s.into() };
        // rig beats ambient (C:\cr is in the ambient set too)
        assert_eq!(lab.label(&p("C:\\cr\\out\\x")).0, "rig");
        assert_eq!(lab.label(&p("C:\\Windows\\Prefetch\\X.pf")).0, "ambient");
        assert_eq!(lab.label(&p("C:\\Windows\\Logs\\a.log")).0, "ambient");
        assert_eq!(lab.label(&k("HKLM\\SOFTWARE\\Python\\PyLauncher")).0, "kept_owner");
        assert_eq!(lab.label(&p("C:\\Windows\\py.exe")).0, "kept_owner");
        assert_eq!(lab.label(&p("C:\\Program Files\\PyLauncher\\x.dll")).0, "kept_owner");
        assert_eq!(lab.label(&k("HKLM\\SOFTWARE\\Classes\\Installer\\Products\\AAAAAAAABBBBCCCCDDDDEEEEEEEEEEEE")).0, "kept_owner");
        assert_eq!(lab.label(&p("C:\\Users\\t\\AppData\\Roaming\\App\\Profiles\\p1")).0, "user_data");
        let (l, r) = lab.label(&p("C:\\Program Files\\App"));
        assert_eq!((l.as_str(), r.as_str()), ("leftover", "default"));
    }

    #[test]
    fn entries_left_and_lists() {
        let run = json!({"entries_left": ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\A"]});
        let l0 = json!({"uninstall": [{"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Old"}]});
        let l2 = json!({"uninstall": [
            {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Old"},
            {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\A", "loc": "C:\\Program Files\\A"},
            {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\B", "loc": "C:\\Program Files"}
        ]});
        let e = kept_entries(&run, &l0, &l2, None);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["loc"], "C:\\Program Files\\A");
        let k = KeptAnchors::from_entries(&e, None);
        assert!(k.check(&Target::Path { path: "C:\\Program Files\\A\\a.exe".into() }).is_some());
        // broad InstallLocation of B is not an anchor
        assert!(k.check(&Target::Path { path: "C:\\Program Files\\Z".into() }).is_none());
        // Without lists-0, "new in lists-2" cannot be told apart from preinstalled: only entries_left count.
        assert_eq!(kept_entries(&json!({}), &Value::Null, &l2, None).len(), 0);
        assert_eq!(kept_entries(&run, &Value::Null, &l2, None).len(), 1);
    }

    #[test]
    fn split_paths_at_kept_install_location() {
        // A new folder holds both the removed app and a product that stays installed.
        let s0 = snap_text(|t| write_d(t, "C:\\Program Files", 0x10, 1, 0));
        let s2 = snap_text(|t| {
            write_d(t, "C:\\Program Files", 0x10, 1, 0);
            write_d(t, "C:\\Program Files\\Vendor", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Vendor\\readme.txt", 7, 0x20, 2, 0);
            write_d(t, "C:\\Program Files\\Vendor\\App", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Vendor\\App\\a.dll", 10, 0x20, 2, 0);
            write_d(t, "C:\\Program Files\\Vendor\\App\\sub", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Vendor\\App\\sub\\b.dll", 5, 0x20, 2, 0);
            write_d(t, "C:\\Program Files\\Vendor\\Launcher", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Vendor\\Launcher\\l.exe", 3, 0x20, 2, 0);
        });
        let entries = vec![json!({"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\L",
                                  "name": "Launcher", "loc": "C:\\Program Files\\Vendor\\Launcher"})];
        let lab = Labeler {
            rig: RigRules::new(&[]),
            ambient: None,
            rules: vec![],
            kept: KeptAnchors::from_entries(&entries, None),
        };
        let (items, n) = split_kept(items::derive(&s0, &s2), &s0, &s2, &lab);
        assert_eq!(n, 1);
        let got: Vec<(String, Option<u64>, String)> = label_items(items, &lab, None)
            .into_iter()
            .map(|i| (i.target.canon_string(), i.size, i.label))
            .collect();
        assert_eq!(
            got,
            vec![
                ("P:C:\\Program Files\\Vendor\\App".to_string(), Some(15), "leftover".to_string()),
                ("P:C:\\Program Files\\Vendor\\Launcher".to_string(), Some(3), "kept_owner".to_string()),
                ("P:C:\\Program Files\\Vendor\\readme.txt".to_string(), Some(7), "leftover".to_string()),
            ]
        );
        // a kept_owner label rule below a collapsed key splits it too
        let s0 = snap_text(|t| write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(0)));
        let s2 = snap_text(|t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Python", 2, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Python\\PyLauncher", 2, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Python\\PythonCore", 2, Some(0), Some(0));
        });
        let lab = Labeler {
            rig: RigRules::new(&[]),
            ambient: None,
            rules: vec![rule("kept_owner", r"^K:HKLM\\SOFTWARE\\Python\\PyLauncher")],
            kept: KeptAnchors::default(),
        };
        let (items, n) = split_kept(items::derive(&s0, &s2), &s0, &s2, &lab);
        assert_eq!(n, 1);
        let got: Vec<(String, String)> =
            label_items(items, &lab, None).into_iter().map(|i| (i.target.canon_string(), i.label)).collect();
        assert_eq!(
            got,
            vec![
                ("K:HKLM\\SOFTWARE\\Python\\PyLauncher".to_string(), "kept_owner".to_string()),
                ("K:HKLM\\SOFTWARE\\Python\\PythonCore".to_string(), "leftover".to_string()),
            ]
        );
    }

    #[test]
    fn split_new_root_at_planted_user_data() {
        // x0-npp-userfiles: user files planted inside the new install root while the app was installed.
        let s0 = snap_text(|t| write_d(t, "C:\\Program Files", 0x10, 1, 0));
        let s2 = snap_text(|t| {
            write_d(t, "C:\\Program Files", 0x10, 1, 0);
            write_d(t, "C:\\Program Files\\Notepad++", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Notepad++\\notepad++.exe", 10, 0x20, 2, 0);
            write_f(t, "C:\\Program Files\\Notepad++\\session-backup.txt", 4, 0x20, 2, 0);
            write_d(t, "C:\\Program Files\\Notepad++\\my-notes", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Notepad++\\my-notes\\todo.txt", 3, 0x20, 2, 0);
            write_d(t, "C:\\Program Files\\Notepad++\\plugins", 0x10, 2, 0);
            write_f(t, "C:\\Program Files\\Notepad++\\plugins\\p.dll", 5, 0x20, 2, 0);
        });
        let rules = vec![
            rule("user_data", r"^P:C:\\Program Files\\Notepad\+\+\\(my-notes|session-backup\.txt)(\\.*)?$"),
            // A user_data top is never split (the whole folder is user data already).
            rule("user_data", r"^P:C:\\Users\\"),
        ];
        let lab = Labeler { rig: RigRules::new(&[]), ambient: None, rules, kept: KeptAnchors::default() };
        let (items, n) = split_kept(items::derive(&s0, &s2), &s0, &s2, &lab);
        assert_eq!(n, 1);
        let got: Vec<(String, Option<u64>, String)> =
            label_items(items, &lab, None).into_iter().map(|i| (i.target.canon_string(), i.size, i.label)).collect();
        assert_eq!(
            got,
            vec![
                ("P:C:\\Program Files\\Notepad++\\my-notes".to_string(), Some(3), "user_data".to_string()),
                ("P:C:\\Program Files\\Notepad++\\notepad++.exe".to_string(), Some(10), "leftover".to_string()),
                ("P:C:\\Program Files\\Notepad++\\plugins".to_string(), Some(5), "leftover".to_string()),
                ("P:C:\\Program Files\\Notepad++\\session-backup.txt".to_string(), Some(4), "user_data".to_string()),
            ]
        );
        // Without a user_data rule below it the root stays one leftover item.
        let lab = Labeler { rig: RigRules::new(&[]), ambient: None, rules: vec![], kept: KeptAnchors::default() };
        let (items, n) = split_kept(items::derive(&s0, &s2), &s0, &s2, &lab);
        assert_eq!((n, items.len()), (0, 1));
        // A collapsed user_data top is not split at user_data matches inside it.
        let s0 = snap_text(|t| write_d(t, "C:\\Users", 0x10, 1, 0));
        let s2 = snap_text(|t| {
            write_d(t, "C:\\Users", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t", 0x10, 2, 0);
            write_f(t, "C:\\Users\\t\\a.txt", 1, 0x20, 2, 0);
        });
        let lab = Labeler {
            rig: RigRules::new(&[]),
            ambient: None,
            rules: vec![rule("user_data", r"^P:C:\\Users\\")],
            kept: KeptAnchors::default(),
        };
        let (items, n) = split_kept(items::derive(&s0, &s2), &s0, &s2, &lab);
        assert_eq!((n, items.len()), (0, 1));
    }

    #[test]
    fn split_rule_opens_container_and_first_rule_wins() {
        // A new Windows container (PackagedCom) holding an app's package registration.
        let s0 = snap_text(|t| write_k(t, "HKLM\\SOFTWARE\\Classes", 1, Some(0), Some(0)));
        let s2 = snap_text(|t| {
            write_k(t, "HKLM\\SOFTWARE\\Classes", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom", 2, Some(1), Some(2));
            write_v(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom", "MaxInstallOrder", 4, 4, 3, "1");
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom\\Package", 2, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom\\Package\\App_1.0.0.0_neutral__abc", 2, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom\\Package\\App_1.0.0.0_neutral__abc\\Class", 2, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom\\ClassIndex", 2, Some(0), Some(0));
            write_d(t, "C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\Caches", 0x10, 1, 0);
            write_f(t, "C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\Caches\\x.db", 3, 0x20, 1, 0);
        });
        let mut split = rule("ambient", r"^K:HKLM\\SOFTWARE\\Classes\\PackagedCom(\\(Package|ClassIndex))?$");
        split.split = true;
        let mut first = rule("leftover", r"\\Caches\\x\.db$");
        first.first = true;
        let lab = Labeler {
            rig: RigRules::new(&[]),
            ambient: None,
            rules: vec![
                split,
                rule("ambient", r"^V:HKLM\\SOFTWARE\\Classes\\PackagedCom\|MaxInstallOrder$"),
                rule("ambient", r"^P:C:\\Users\\[^\\]+\\AppData\\Local\\Microsoft\\Windows\\Caches(\\.*)?$"),
                first,
            ],
            kept: KeptAnchors::default(),
        };
        let (items, n) = split_containers(items::derive(&s0, &s2), &s2, &lab);
        assert_eq!(n, 3, "PackagedCom, Package and ClassIndex are opened");
        let got: Vec<(String, String)> =
            label_items(items, &lab, None).into_iter().map(|i| (i.target.canon_string(), i.label)).collect();
        let want = vec![
            ("P:C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\Caches", "ambient"),
            ("K:HKLM\\SOFTWARE\\Classes\\PackagedCom", "ambient"),
            ("K:HKLM\\SOFTWARE\\Classes\\PackagedCom\\ClassIndex", "ambient"),
            ("K:HKLM\\SOFTWARE\\Classes\\PackagedCom\\Package", "ambient"),
            ("K:HKLM\\SOFTWARE\\Classes\\PackagedCom\\Package\\App_1.0.0.0_neutral__abc", "leftover"),
            ("V:HKLM\\SOFTWARE\\Classes\\PackagedCom|MaxInstallOrder", "ambient"),
        ];
        let want: Vec<(String, String)> = want.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        assert_eq!(got, want);
        // the Caches dir is ambient as a collapsed item (no split rule), but a `first` rule beats ambient
        assert_eq!(lab.label(&Target::Path { path: "C:\\Users\\u\\AppData\\Local\\Microsoft\\Windows\\Caches\\x.db".into() }).0, "leftover");
    }

    #[test]
    fn same_segments_only_for_complete_lists() {
        assert!(same_segments("C:\\A;C:\\B\\", "c:\\a;;C:\\B;"));
        assert!(same_segments("%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;", "%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps"));
        assert!(!same_segments("C:\\A", "C:\\B"));
        assert!(!same_segments("C:\\A;C:\\B", "C:\\A;C:\\B;C:\\App\\bin"));
        assert!(!same_segments("#0123456789abcdef", "#0123456789abcdef"));
        let long = format!("{};C:\\x", "a".repeat(crate::snap::PREVIEW_MAX));
        assert!(!same_segments(&long, &long));
        let lab = Labeler { rig: RigRules::new(&[]), ambient: None, rules: vec![], kept: KeptAnchors::default() };
        let t = |b: &str, a: &str| Target::RegValueChanged {
            path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment".into(),
            name: "Path".into(),
            before: b.into(),
            after: a.into(),
        };
        assert_eq!(lab.label(&t("C:\\A;C:\\B", "C:\\A;C:\\B;")).0, "ambient");
        assert_eq!(lab.label(&t("C:\\A;C:\\B", "C:\\A;C:\\B;C:\\App")).0, "leftover");
    }

    #[test]
    fn end_to_end_truth_items() {
        let s0 = snap_text(|t| {
            write_d(t, "C:\\cr", 0x10, 1, 0);
            write_k(t, "HKLM\\SOFTWARE", 1, Some(1), Some(1));
            write_v(t, "HKLM\\SOFTWARE", "Stable", 4, 4, 7, "1");
            write_k(t, "HKLM\\SOFTWARE\\Classes", 1, Some(0), Some(0));
        });
        let s2 = snap_text(|t| {
            write_d(t, "C:\\cr", 0x10, 2, 0);
            write_f(t, "C:\\cr\\out.json", 1, 0x20, 2, 0);
            write_d(t, "C:\\Program Files\\App", 0x10, 2, 0);
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Classes", 2, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Classes", "AppVal", 1, 2, 9, "v");
            write_k(t, "HKLM\\SOFTWARE\\App", 2, Some(0), Some(0));
        });
        let lab = Labeler { rig: RigRules::new(&[&s0, &s2]), ambient: None, rules: vec![], kept: KeptAnchors::default() };
        let items = label_items(items::derive(&s0, &s2), &lab, None);
        let got: Vec<(String, String)> = items.iter().map(|i| (i.target.canon_string(), i.label.clone())).collect();
        assert_eq!(
            got,
            vec![
                ("P:C:\\cr\\out.json".to_string(), "rig".to_string()),
                ("P:C:\\Program Files\\App".to_string(), "leftover".to_string()),
                ("K:HKLM\\SOFTWARE\\App".to_string(), "leftover".to_string()),
                ("V:HKLM\\SOFTWARE\\Classes|AppVal".to_string(), "leftover".to_string()),
            ]
        );
        let tf = summarize("x", items);
        assert_eq!(tf.counts["leftover"], 3);
        assert_eq!(tf.counts["rig"], 1);
    }

    #[test]
    fn store_self_updates_are_ambient() {
        let l0 = json!({"appx": [
            {"full_name": "Microsoft.Windows.Photos_26.1.0.0_x64__8wekyb3d8bbwe", "install_location": "C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_26.1.0.0_x64__8wekyb3d8bbwe", "sparse": false},
            {"full_name": "Microsoft.VisualStudioCode_1.0.0.0_neutral__8wekyb3d8bbwe", "install_location": "C:\\Program Files\\Microsoft VS Code", "sparse": true}
        ]});
        let l2 = json!({"appx": [
            {"full_name": "Microsoft.Windows.Photos_2026.1.0.0_x64__8wekyb3d8bbwe", "install_location": "C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_2026.1.0.0_x64__8wekyb3d8bbwe", "sparse": false},
            {"full_name": "Microsoft.VCLibs.140.00_14.0.1.0_x86__8wekyb3d8bbwe", "install_location": "C:\\Program Files\\WindowsApps\\Microsoft.VCLibs.140.00_14.0.1.0_x86__8wekyb3d8bbwe", "sparse": false},
            {"full_name": "Vendor.App_1.0.0.0_x64__abcdefghijklm", "install_location": "C:\\Program Files\\WindowsApps\\Vendor.App_1.0.0.0_x64__abcdefghijklm", "sparse": false},
            {"full_name": "NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww", "install_location": "C:\\Program Files\\Notepad++", "sparse": true}
        ]});
        let upd = store_updates(&l0, &l2);
        let fams: BTreeSet<&str> = upd.iter().map(|(_, f)| f.as_str()).collect();
        assert_eq!(fams.into_iter().collect::<Vec<_>>(), vec!["Microsoft.VCLibs.140.00_8wekyb3d8bbwe", "Microsoft.Windows.Photos_8wekyb3d8bbwe"]);
        let it = |t: Target, l: &str| TruthItem { target: t, label: l.into(), rule: String::new(), size: None, lwt: None, dir: None, in_s1: None };
        let mut items = vec![
            it(Target::Path { path: "C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_2026.1.0.0_x64__8wekyb3d8bbwe\\a.dll".into() }, "leftover"),
            it(Target::RegKey { path: "HKLM\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Microsoft.Windows.Photos_8wekyb3d8bbwe".into() }, "leftover"),
            it(Target::Path { path: "C:\\Program Files\\Notepad++\\x".into() }, "leftover"),
            it(Target::RegKey { path: "HKLM\\SOFTWARE\\Microsoft.Windows.Photos_8wekyb3d8bbwe".into() }, "kept_owner"),
        ];
        assert_eq!(relabel_store_updates(&mut items, &upd), 2);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(labels, vec!["ambient", "ambient", "leftover", "kept_owner"]);
        assert!(store_updates(&Value::Null, &l2).is_empty());
    }
}
