//! `rigtool score` (RIG.md §7): match offered plan items against the truth.

use crate::canon::{self, CiStr, CiString, LinkMap, PrefixIndex};
use crate::deny::Deny;
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::snap::{self, LoadOpts, Snap};
use crate::target::Target;
use crate::truth::{TruthFile, TruthItem};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------------------------
// Plan JSON
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlanItem {
    pub target: Target,
    #[serde(default)]
    pub band: String,
    #[serde(default)]
    pub preselected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Plan {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub items: Vec<PlanItem>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Band {
    Safe,
    Likely,
    Weak,
    Blocked,
    Unknown,
}

pub fn band_of(s: &str) -> Band {
    match s.to_ascii_lowercase().as_str() {
        "safe" => Band::Safe,
        "likely" => Band::Likely,
        "weak" => Band::Weak,
        "blocked" => Band::Blocked,
        _ => Band::Unknown,
    }
}

// ---------------------------------------------------------------------------------------------
// Truth index
// ---------------------------------------------------------------------------------------------

pub struct TruthIdx {
    pub items: Vec<TruthItem>,
    p: PrefixIndex<usize>,
    k: PrefixIndex<usize>,
    vkey: PrefixIndex<usize>,
    vexact: HashMap<CiString, Vec<usize>>,
}

fn segments(s: &str) -> Vec<&str> {
    let sep = if s.contains('\0') { '\0' } else { ';' };
    s.split(sep).map(str::trim).filter(|x| !x.is_empty()).collect()
}

fn seg_eq(a: &str, b: &str) -> bool {
    canon::ci_eq(a.trim().trim_end_matches('\\'), b.trim().trim_end_matches('\\'))
}

fn has_segment(data: &str, seg: &str) -> bool {
    segments(data).iter().any(|s| seg_eq(s, seg))
}

impl TruthIdx {
    pub fn new(items: Vec<TruthItem>, sid: Option<&str>) -> TruthIdx {
        // Canonicalise and drop duplicates (a truth file built from a snap that captured a hive under two
        // names, e.g. HKU\S-1-5-18 and HKU\.DEFAULT, would otherwise count those items twice).
        let mut seen = std::collections::HashSet::new();
        let items: Vec<TruthItem> = items
            .into_iter()
            .map(|mut i| {
                i.target = i.target.canonical(sid);
                i
            })
            .filter(|i| seen.insert(canon::fold(&i.target.canon_string())))
            .collect();
        let (mut p, mut k, mut vk) = (Vec::new(), Vec::new(), Vec::new());
        let mut vexact: HashMap<CiString, Vec<usize>> = HashMap::new();
        for (n, i) in items.iter().enumerate() {
            match &i.target {
                Target::Path { path } => p.push((path.clone(), n)),
                Target::RegKey { path } => k.push((path.clone(), n)),
                Target::RegValue { path, name } | Target::RegValueChanged { path, name, .. } => {
                    vk.push((path.clone(), n));
                    vexact.entry(CiString(format!("{path}|{name}"))).or_default().push(n);
                }
                _ => {}
            }
        }
        TruthIdx { items, p: PrefixIndex::new(p), k: PrefixIndex::new(k), vkey: PrefixIndex::new(vk), vexact }
    }

    fn values(&self, key: &str, name: &str) -> &[usize] {
        self.vexact.get(CiStr::new(&format!("{key}|{name}"))).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Truth items `o` covers: equal, or contained in `o`.
    pub fn covers(&self, o: &Target) -> Vec<usize> {
        match o {
            Target::Path { path } => self.p.under_or_eq(path),
            Target::RegKey { path } => {
                let mut v = self.k.under_or_eq(path);
                v.extend(self.vkey.under_or_eq(path));
                v
            }
            Target::RegValue { path, name } => self
                .values(path, name)
                .iter()
                .copied()
                .filter(|&i| matches!(self.items[i].target, Target::RegValue { .. }))
                .collect(),
            Target::RegMultiSzSegment { path, name, segment } => self
                .values(path, name)
                .iter()
                .copied()
                .filter(|&i| match &self.items[i].target {
                    Target::RegValueChanged { before, after, .. } => {
                        has_segment(after, segment) && !has_segment(before, segment)
                    }
                    _ => false,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Truth items `o` is strictly inside (partial).
    pub fn partial(&self, o: &Target) -> Vec<usize> {
        match o {
            Target::Path { path } => canon::parent(path).map(|p| self.p.ancestors_or_eq(p)).unwrap_or_default(),
            Target::RegKey { path } => canon::parent(path).map(|p| self.k.ancestors_or_eq(p)).unwrap_or_default(),
            Target::RegValue { path, .. } => self.k.ancestors_or_eq(path),
            Target::RegMultiSzSegment { path, name, .. } => {
                let mut v = self.k.ancestors_or_eq(path);
                v.extend(
                    self.values(path, name).iter().copied().filter(|&i| matches!(self.items[i].target, Target::RegValue { .. })),
                );
                v
            }
            _ => Vec::new(),
        }
    }
}

/// (exists, known) of a primitive target in a snap. `known` = the capture would have recorded it.
pub fn exists(s: &Snap, o: &Target) -> (bool, bool) {
    match o {
        Target::Path { path } => {
            if s.has_path(path) {
                (true, true)
            } else {
                (false, s.captures_path(path))
            }
        }
        Target::RegKey { path } => {
            if s.has_key(path) {
                (true, true)
            } else {
                (false, s.captures_key(path))
            }
        }
        Target::RegValue { path, name } => {
            if s.value(path, name).is_some() {
                return (true, true);
            }
            (false, s.n_values > 0 && s.values_known(path))
        }
        Target::RegMultiSzSegment { path, name, segment } => match s.value(path, name) {
            Some(v) => {
                let found = has_segment(&v.preview, segment);
                // Only REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ previews hold the data, and only when they were
                // not cut at PREVIEW_MAX; otherwise a miss is unknown, never "gone".
                let complete = matches!(v.typ, 1 | 2 | 7) && v.preview.chars().count() < crate::snap::PREVIEW_MAX;
                (found, found || complete)
            }
            None => exists(s, &Target::RegValue { path: path.clone(), name: name.clone() }),
        },
        _ => (false, false),
    }
}

// ---------------------------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug)]
pub struct ItemOutcome {
    pub target: String,
    pub band: String,
    pub preselected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner: Option<String>,
    pub outcome: String,
    pub covers: usize,
    pub partial: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct KindRecall {
    pub n: usize,
    pub covered: usize,
    pub recall: Option<f64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Missed {
    pub target: String,
    pub label: String,
    pub partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ToolScore {
    pub app: String,
    pub tool: String,
    pub mode: String,
    pub plan_file: String,
    pub offered_n: usize,
    pub truth_n: usize,
    pub covered_listed: usize,
    pub covered_visible: usize,
    pub covered_safe: usize,
    pub recall_listed: Option<f64>,
    pub recall_visible: Option<f64>,
    pub recall_safe: Option<f64>,
    /// Same three, counting only coverage by offered items whose outcome is not `danger` (a broad
    /// pre-existing folder or key covers everything below it but must not earn recall).
    pub covered_listed_nd: usize,
    pub covered_visible_nd: usize,
    pub covered_safe_nd: usize,
    pub recall_listed_nd: Option<f64>,
    pub recall_visible_nd: Option<f64>,
    pub recall_safe_nd: Option<f64>,
    pub partial_n: usize,
    pub safe_n: usize,
    pub safe_not_gone: usize,
    pub safe_hits: usize,
    pub precision_safe: Option<f64>,
    pub danger_listed: usize,
    pub danger_preselected: usize,
    pub userdata_preselected: usize,
    pub outcomes: BTreeMap<String, usize>,
    pub per_kind: BTreeMap<String, KindRecall>,
    pub per_scanner: BTreeMap<String, BTreeMap<String, usize>>,
    pub missed: Vec<Missed>,
    pub danger: Vec<ItemOutcome>,
    pub items: Vec<ItemOutcome>,
}

fn ratio(a: usize, b: usize) -> Option<f64> {
    if b == 0 { None } else { Some(a as f64 / b as f64) }
}

pub const OUTCOMES: [&str; 5] = ["danger", "hit", "ambient", "gone", "other"];
const KINDS: [&str; 4] = ["Path", "RegKey", "RegValue", "RegValueChanged"];

pub struct Ctx<'a> {
    pub truth: &'a TruthIdx,
    pub s0: &'a Snap,
    pub s2: &'a Snap,
    pub deny: &'a Deny,
    pub sid: Option<&'a str>,
    /// Registry links recorded in snap0/snap2 (beyond the ones `canon_reg` folds itself).
    pub links: &'a LinkMap,
}

fn is_recall_label(l: &str) -> bool {
    l == "leftover" || l == "user_data"
}

/// Package family name of a package full name (`Name_Version_Arch_ResourceId_PublisherId`).
pub fn package_family(full_name: &str) -> Option<String> {
    let parts: Vec<&str> = full_name.split('_').collect();
    if parts.len() == 5 && !parts[0].is_empty() && !parts[4].is_empty() {
        Some(format!("{}_{}", parts[0], parts[4]))
    } else {
        None
    }
}

/// Truth items that removing package `full_name` through the package API takes away: everything whose
/// canonical string names the package (full name or family name, e.g. AppModel / Appx / PolicyCache keys,
/// AppRepository files, `%LOCALAPPDATA%\Packages\<family>`, AppIso firewall rules) and the package's
/// AppContainer SID mapping (`AppContainer\Mappings\<S-1-15-2-...>`, whose `Moniker` is the family name).
pub fn package_covers(t: &TruthIdx, full_name: &str, s2: &Snap) -> Vec<usize> {
    let Some(family) = package_family(full_name) else { return Vec::new() };
    let full = canon::fold(full_name);
    let fam = canon::fold(&family);
    let mut out = Vec::new();
    for (i, ti) in t.items.iter().enumerate() {
        let cs = canon::fold(&ti.target.canon_string());
        let mut hit = cs.contains(&full) || cs.contains(&fam);
        if !hit
            && let Target::RegKey { path } = &ti.target
            && canon::fold(path).contains("\\appcontainer\\mappings\\s-1-15-2-")
            && let Some(v) = s2.value(path, "Moniker")
        {
            hit = canon::ci_eq(v.preview.trim(), &family);
        }
        // A packaged-COM class index entry `ClassIndex\{CLSID}` names its package in a child key.
        if !hit
            && let Target::RegKey { path } = &ti.target
            && canon::fold(path).contains("\\packagedcom\\classindex\\{")
        {
            hit = s2.key(&format!("{path}\\{full_name}")).is_some();
        }
        if hit {
            out.push(i);
        }
    }
    out
}

pub fn score_plan(cx: &Ctx, app: &str, plan: &Plan, plan_file: &str) -> ToolScore {
    let t = cx.truth;
    let mut sc = ToolScore {
        app: app.to_string(),
        tool: plan.tool.clone(),
        mode: plan.mode.clone(),
        plan_file: plan_file.to_string(),
        offered_n: plan.items.len(),
        ..Default::default()
    };
    for o in OUTCOMES {
        sc.outcomes.insert(o.to_string(), 0);
    }
    let n = t.items.len();
    let mut cov_any = vec![false; n];
    let mut cov_vis = vec![false; n];
    let mut cov_safe = vec![false; n];
    let mut cov_any_nd = vec![false; n];
    let mut cov_vis_nd = vec![false; n];
    let mut cov_safe_nd = vec![false; n];
    let mut part_any = vec![false; n];

    for it in &plan.items {
        // Canonical spelling, then any registry link the snaps recorded (an offered alias path matches
        // the data the capture holds under the link's target).
        let o = it.target.canonical(cx.sid).map_reg(|k| cx.links.resolve(k));
        let band = band_of(&it.band);
        let prims = o.primitives();
        // An offered item that is absent from snap2 (and inside a captured root) is a no-op: it can
        // neither harm a kept/denied item nor clean a leftover. Typical for plans recorded on another
        // run (the old UT/BCU outputs list what the vendor uninstaller also removed).
        let all_gone = !prims.is_empty()
            && prims.iter().all(|p| {
                let (e, k) = exists(cx.s2, p);
                !e && k
            });
        let mut covers: BTreeSet<usize> = BTreeSet::new();
        let mut partial: BTreeSet<usize> = BTreeSet::new();
        let is_pkg = matches!(o, Target::AppxPackage { .. });
        if !all_gone {
            for p in &prims {
                covers.extend(t.covers(p));
                partial.extend(t.partial(p));
            }
            if let Target::AppxPackage { full_name } = &o {
                covers.extend(package_covers(t, full_name, cx.s2));
            }
        }
        for &i in &partial {
            part_any[i] = true;
        }

        let mut reasons = Vec::new();
        for p in prims.iter().filter(|_| !all_gone) {
            if exists(cx.s0, p).0 {
                reasons.push(format!("existed in snap0: {}", p.canon_string()));
            }
        }
        for &i in &covers {
            if t.items[i].label == "kept_owner" {
                reasons.push(format!("covers kept_owner {}", t.items[i].target.canon_string()));
            }
        }
        for &i in &partial {
            if t.items[i].label == "kept_owner" {
                reasons.push(format!("inside kept_owner {}", t.items[i].target.canon_string()));
            }
        }
        // Removing a package through the package API is the sanctioned route into the deployment stores
        // the deny list protects from raw deletes, so a package offer is not checked against it.
        if !all_gone
            && !is_pkg
            && let Some(w) = cx.deny.check(&o).or_else(|| prims.iter().find_map(|p| cx.deny.check(p)))
        {
            reasons.push(w);
        }
        let touched: Vec<usize> = covers.iter().chain(partial.iter()).copied().collect();
        let outcome = if !reasons.is_empty() {
            "danger"
        } else if touched.iter().any(|&i| is_recall_label(&t.items[i].label)) {
            "hit"
        } else if !touched.is_empty() && touched.iter().all(|&i| matches!(t.items[i].label.as_str(), "ambient" | "rig")) {
            "ambient"
        } else if all_gone {
            "gone"
        } else {
            "other"
        };
        let visible = matches!(band, Band::Safe | Band::Likely);
        for &i in &covers {
            cov_any[i] = true;
            cov_vis[i] |= visible;
            cov_safe[i] |= band == Band::Safe;
            if outcome != "danger" {
                cov_any_nd[i] = true;
                cov_vis_nd[i] |= visible;
                cov_safe_nd[i] |= band == Band::Safe;
            }
        }
        *sc.outcomes.get_mut(outcome).unwrap() += 1;
        let scanner = it.scanner.clone().unwrap_or_else(|| "-".into());
        *sc.per_scanner.entry(scanner).or_default().entry(outcome.to_string()).or_default() += 1;
        if band == Band::Safe {
            sc.safe_n += 1;
            if outcome != "gone" {
                sc.safe_not_gone += 1;
            }
            if outcome == "hit" {
                sc.safe_hits += 1;
            }
        }
        if it.preselected && touched.iter().any(|&i| t.items[i].label == "user_data") {
            sc.userdata_preselected += 1;
        }
        let io = ItemOutcome {
            target: o.canon_string(),
            band: it.band.clone(),
            preselected: it.preselected,
            scanner: it.scanner.clone(),
            outcome: outcome.to_string(),
            covers: covers.len(),
            partial: partial.len(),
            reasons,
        };
        if outcome == "danger" {
            sc.danger_listed += 1;
            if it.preselected {
                sc.danger_preselected += 1;
            }
            sc.danger.push(io.clone());
        }
        sc.items.push(io);
    }

    for k in KINDS {
        sc.per_kind.insert(k.to_string(), KindRecall::default());
    }
    for (i, ti) in t.items.iter().enumerate() {
        if !is_recall_label(&ti.label) {
            continue;
        }
        sc.truth_n += 1;
        let kr = sc.per_kind.entry(ti.target.kind().to_string()).or_default();
        kr.n += 1;
        if cov_any[i] {
            kr.covered += 1;
            sc.covered_listed += 1;
        } else {
            if part_any[i] {
                sc.partial_n += 1;
            }
            sc.missed.push(Missed {
                target: ti.target.canon_string(),
                label: ti.label.clone(),
                partial: part_any[i],
                size: ti.size,
            });
        }
        if cov_vis[i] {
            sc.covered_visible += 1;
        }
        if cov_safe[i] {
            sc.covered_safe += 1;
        }
        sc.covered_listed_nd += cov_any_nd[i] as usize;
        sc.covered_visible_nd += cov_vis_nd[i] as usize;
        sc.covered_safe_nd += cov_safe_nd[i] as usize;
    }
    for kr in sc.per_kind.values_mut() {
        kr.recall = ratio(kr.covered, kr.n);
    }
    sc.recall_listed = ratio(sc.covered_listed, sc.truth_n);
    sc.recall_visible = ratio(sc.covered_visible, sc.truth_n);
    sc.recall_safe = ratio(sc.covered_safe, sc.truth_n);
    sc.recall_listed_nd = ratio(sc.covered_listed_nd, sc.truth_n);
    sc.recall_visible_nd = ratio(sc.covered_visible_nd, sc.truth_n);
    sc.recall_safe_nd = ratio(sc.covered_safe_nd, sc.truth_n);
    sc.precision_safe = ratio(sc.safe_hits, sc.safe_not_gone);
    sc
}

// ---------------------------------------------------------------------------------------------
// Aggregation and output
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Clone, Debug, Default)]
pub struct AppScore {
    pub id: String,
    pub dir: String,
    pub sid: Option<String>,
    pub truth_counts: BTreeMap<String, usize>,
    pub ambient_by_run: BTreeMap<String, usize>,
    pub tools: Vec<ToolScore>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct MacroScore {
    pub tool: String,
    pub apps: usize,
    pub truth_n: usize,
    pub recall_listed: Option<f64>,
    pub recall_visible: Option<f64>,
    pub recall_safe: Option<f64>,
    pub recall_listed_nd: Option<f64>,
    pub recall_visible_nd: Option<f64>,
    pub recall_safe_nd: Option<f64>,
    pub precision_safe: Option<f64>,
    pub partial_n: usize,
    pub danger_listed: usize,
    pub danger_preselected: usize,
    pub userdata_preselected: usize,
    pub per_kind_recall: BTreeMap<String, Option<f64>>,
    pub outcomes: BTreeMap<String, usize>,
}

fn mean(v: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    let xs: Vec<f64> = v.flatten().collect();
    if xs.is_empty() { None } else { Some(xs.iter().sum::<f64>() / xs.len() as f64) }
}

pub fn tool_label(s: &ToolScore) -> String {
    if s.mode.is_empty() || s.mode == "post" { s.tool.clone() } else { format!("{}/{}", s.tool, s.mode) }
}

pub fn macro_scores(apps: &[AppScore]) -> Vec<MacroScore> {
    let mut by: BTreeMap<String, Vec<&ToolScore>> = BTreeMap::new();
    for a in apps {
        for t in &a.tools {
            by.entry(tool_label(t)).or_default().push(t);
        }
    }
    by.into_iter()
        .map(|(tool, v)| {
            let mut m = MacroScore {
                tool,
                apps: v.iter().filter(|t| t.truth_n > 0).count(),
                truth_n: v.iter().map(|t| t.truth_n).sum(),
                recall_listed: mean(v.iter().map(|t| t.recall_listed)),
                recall_visible: mean(v.iter().map(|t| t.recall_visible)),
                recall_safe: mean(v.iter().map(|t| t.recall_safe)),
                recall_listed_nd: mean(v.iter().map(|t| t.recall_listed_nd)),
                recall_visible_nd: mean(v.iter().map(|t| t.recall_visible_nd)),
                recall_safe_nd: mean(v.iter().map(|t| t.recall_safe_nd)),
                precision_safe: mean(v.iter().map(|t| t.precision_safe)),
                partial_n: v.iter().map(|t| t.partial_n).sum(),
                danger_listed: v.iter().map(|t| t.danger_listed).sum(),
                danger_preselected: v.iter().map(|t| t.danger_preselected).sum(),
                userdata_preselected: v.iter().map(|t| t.userdata_preselected).sum(),
                ..Default::default()
            };
            for k in KINDS {
                m.per_kind_recall
                    .insert(k.to_string(), mean(v.iter().map(|t| t.per_kind.get(k).and_then(|r| r.recall))));
            }
            for o in OUTCOMES {
                m.outcomes.insert(o.to_string(), v.iter().map(|t| t.outcomes.get(o).copied().unwrap_or(0)).sum());
            }
            m
        })
        .collect()
}

fn pct(x: Option<f64>) -> String {
    match x {
        Some(v) => format!("{:.1}%", v * 100.0),
        None => "-".into(),
    }
}

/// For text inside inline code in list items (pipes need no escaping there).
fn md_escape(s: &str) -> String {
    s.replace('\0', "\\0").replace('`', "'")
}

pub fn render_md(apps: &[AppScore], macros: &[MacroScore]) -> String {
    let mut m = String::new();
    let _ = writeln!(m, "# Rig score\n");
    let _ = writeln!(m, "Truth recall denominator = `leftover` + `user_data`. Outcomes per offered item: gone (absent from snap2: a no-op) first, then danger > hit > ambient > other.");
    let _ = writeln!(m, "`*_nd` recall counts only coverage by offered items that are not `danger`.\n");
    let _ = writeln!(m, "## Macro (mean over apps per tool)\n");
    let _ = writeln!(
        m,
        "| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | Path | RegKey | RegValue | RegValueChanged |"
    );
    let _ = writeln!(m, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for x in macros {
        let pk = |k: &str| pct(x.per_kind_recall.get(k).copied().flatten());
        let _ = writeln!(
            m,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            x.tool,
            x.apps,
            x.truth_n,
            pct(x.recall_listed),
            pct(x.recall_visible),
            pct(x.recall_safe),
            pct(x.recall_listed_nd),
            pct(x.recall_visible_nd),
            pct(x.recall_safe_nd),
            pct(x.precision_safe),
            x.partial_n,
            x.danger_listed,
            x.danger_preselected,
            x.userdata_preselected,
            pk("Path"),
            pk("RegKey"),
            pk("RegValue"),
            pk("RegValueChanged")
        );
    }
    let _ = writeln!(m, "\n## Per app\n");
    let _ = writeln!(
        m,
        "| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger_listed | danger_presel | userdata_presel | hit | danger | ambient | gone | other |"
    );
    let _ = writeln!(m, "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for a in apps {
        for t in &a.tools {
            let o = |k: &str| t.outcomes.get(k).copied().unwrap_or(0);
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                a.id,
                tool_label(t),
                t.offered_n,
                t.truth_n,
                pct(t.recall_listed),
                pct(t.recall_visible),
                pct(t.recall_safe),
                pct(t.recall_listed_nd),
                pct(t.recall_visible_nd),
                pct(t.recall_safe_nd),
                pct(t.precision_safe),
                t.partial_n,
                t.danger_listed,
                t.danger_preselected,
                t.userdata_preselected,
                o("hit"),
                o("danger"),
                o("ambient"),
                o("gone"),
                o("other")
            );
        }
    }
    let _ = writeln!(m, "\n## Per-kind recall (listed)\n");
    let _ = writeln!(m, "| app | tool | Path | RegKey | RegValue | RegValueChanged |");
    let _ = writeln!(m, "|---|---|---:|---:|---:|---:|");
    for a in apps {
        for t in &a.tools {
            let k = |n: &str| {
                t.per_kind.get(n).map(|r| format!("{}/{} {}", r.covered, r.n, pct(r.recall))).unwrap_or_default()
            };
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} | {} | {} |",
                a.id,
                tool_label(t),
                k("Path"),
                k("RegKey"),
                k("RegValue"),
                k("RegValueChanged")
            );
        }
    }
    let _ = writeln!(m, "\n## Truth labels and ambient removal\n");
    for a in apps {
        let c = a.truth_counts.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
        let r = if a.ambient_by_run.is_empty() {
            "no ambient set".to_string()
        } else {
            a.ambient_by_run.iter().map(|(k, v)| format!("{k} removed {v}")).collect::<Vec<_>>().join(", ")
        };
        let _ = writeln!(m, "- **{}**: {c}; ambient: {r}", a.id);
    }
    let _ = writeln!(m, "\n## Danger items\n");
    let mut any = false;
    for a in apps {
        for t in &a.tools {
            for d in &t.danger {
                any = true;
                let _ = writeln!(
                    m,
                    "- {} / {}: `{}` ({}{}) - {}",
                    a.id,
                    tool_label(t),
                    md_escape(&d.target),
                    d.band,
                    if d.preselected { ", preselected" } else { "" },
                    md_escape(&d.reasons.join("; "))
                );
            }
        }
    }
    if !any {
        let _ = writeln!(m, "None.");
    }
    let _ = writeln!(m, "\n## Missed truth items (first 50 per app and tool; full list in the JSON)\n");
    for a in apps {
        for t in &a.tools {
            if t.missed.is_empty() {
                continue;
            }
            let _ = writeln!(m, "### {} / {} ({} missed)\n", a.id, tool_label(t), t.missed.len());
            for x in t.missed.iter().take(50) {
                let _ = writeln!(
                    m,
                    "- `{}` [{}]{}",
                    md_escape(&x.target),
                    x.label,
                    if x.partial { " (partial)" } else { "" }
                );
            }
            let _ = writeln!(m);
        }
    }
    m
}

// ---------------------------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------------------------

pub struct ScoreArgs {
    pub set: Vec<PathBuf>,
    pub plans: Vec<PathBuf>,
    pub truth: Option<PathBuf>,
    pub s0: Option<PathBuf>,
    pub s2: Option<PathBuf>,
    pub deny: Option<PathBuf>,
    pub sid: Option<String>,
    pub json: Option<PathBuf>,
    pub md: Option<PathBuf>,
}

struct AppInput {
    id: String,
    dir: String,
    truth: PathBuf,
    s0: PathBuf,
    s2: PathBuf,
    plans: Vec<PathBuf>,
    deny: Option<PathBuf>,
}

fn app_from_dir(d: &Path, deny: &Option<PathBuf>) -> Result<AppInput> {
    let truth = d.join("truth.json");
    if !truth.is_file() {
        bail!("{}: no truth.json", d.display());
    }
    let s0 = snap::find_phase_file(d, "snap", "0", ".tsv.gz").with_context(|| format!("{}: no snap-0", d.display()))?;
    let s2 = snap::find_phase_file(d, "snap", "2", ".tsv.gz").with_context(|| format!("{}: no snap-2", d.display()))?;
    let mut plans: Vec<PathBuf> = std::fs::read_dir(d.join("plans"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("json")))
                .collect()
        })
        .unwrap_or_default();
    plans.sort();
    let deny = deny.clone().or_else(|| {
        let p = d.parent()?.parent()?.join("truth").join("deny.json");
        p.is_file().then_some(p)
    });
    Ok(AppInput {
        id: d.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
        dir: d.display().to_string(),
        truth,
        s0,
        s2,
        plans,
        deny,
    })
}

fn score_app(a: &AppInput, sid_arg: Option<&str>) -> Result<AppScore> {
    let tf: TruthFile = jsonio::read(&a.truth)?;
    let s0 = Snap::load(&a.s0, LoadOpts::default())?;
    let s2 = Snap::load(&a.s2, LoadOpts::default())?;
    let sid = sid_arg.map(str::to_string).or_else(|| tf.sid.clone()).or_else(|| s0.guess_user_sid());
    let deny = match &a.deny {
        Some(p) => Deny::load(p, sid.as_deref())?,
        None => Deny::default(),
    };
    let id = if tf.id.is_empty() { a.id.clone() } else { tf.id.clone() };
    let truth_counts = tf.counts.clone();
    let ambient_by_run = tf.ambient_by_run.clone();
    let idx = TruthIdx::new(tf.items, sid.as_deref());
    let links = LinkMap::new(s0.reg_links().into_iter().chain(s2.reg_links()));
    let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: sid.as_deref(), links: &links };
    let mut tools = Vec::new();
    for p in &a.plans {
        let plan: Plan = jsonio::read(p)?;
        if !plan.app.is_empty() && !plan.app.eq_ignore_ascii_case(&id) {
            eprintln!("score: warning: {} is for app {:?}, scoring it against {id:?}", p.display(), plan.app);
        }
        let s = score_plan(&cx, &id, &plan, &p.display().to_string());
        eprintln!(
            "score: {id} / {}: offered {} truth {} recall_listed {} danger {}",
            tool_label(&s),
            s.offered_n,
            s.truth_n,
            pct(s.recall_listed),
            s.danger_listed
        );
        tools.push(s);
    }
    Ok(AppScore { id, dir: a.dir.clone(), sid, truth_counts, ambient_by_run, tools })
}

pub fn cmd_score(a: &ScoreArgs) -> Result<()> {
    let mut inputs = Vec::new();
    for d in &a.set {
        inputs.push(app_from_dir(d, &a.deny)?);
    }
    if !a.plans.is_empty() {
        let truth = a.truth.clone().context("--truth is required with --plan")?;
        let s0 = a.s0.clone().context("--s0 is required with --plan")?;
        let s2 = a.s2.clone().context("--s2 is required with --plan")?;
        inputs.push(AppInput {
            id: String::new(),
            dir: truth.parent().map(|p| p.display().to_string()).unwrap_or_default(),
            truth,
            s0,
            s2,
            plans: a.plans.clone(),
            deny: a.deny.clone(),
        });
    }
    if inputs.is_empty() {
        bail!("score: give --set APPDIR... or --plan/--truth/--s0/--s2");
    }
    let mut apps = Vec::new();
    for i in &inputs {
        apps.push(score_app(i, a.sid.as_deref())?);
    }
    let macros = macro_scores(&apps);
    let out = serde_json::json!({ "schema": "purge.rig.score/1", "macro": macros, "apps": apps });
    if let Some(j) = &a.json {
        jsonio::write(j, &out)?;
    }
    let md = render_md(&apps, &macros);
    match &a.md {
        Some(p) => std::fs::write(p, md).with_context(|| format!("write {}", p.display()))?,
        None => print!("{md}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snap::{write_d, write_f, write_k, write_v};
    use crate::testutil::snap_with_roots;
    use serde_json::json;

    const SID: &str = "S-1-5-21-7-7-7-1001";

    fn ti(t: Target, label: &str) -> TruthItem {
        TruthItem { target: t, label: label.into(), rule: "test".into(), size: None, lwt: None, dir: None, in_s1: None }
    }

    fn fixture() -> (Snap, Snap, TruthIdx) {
        let roots = ["HKLM\\SOFTWARE", &format!("HKU\\{SID}"), "C:\\ProgramData", "C:\\Users"];
        let s0 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Clients", 1, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Env", 1, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Env", "Path", 2, 4, 1, "C:\\Windows;C:\\Tools");
            write_k(t, &format!("HKU\\{SID}"), 1, Some(0), Some(1));
            write_k(t, &format!("HKU\\{SID}\\Software"), 1, Some(0), Some(0));
            write_d(t, "C:\\ProgramData\\Microsoft", 0x10, 1, 0);
            write_f(t, "C:\\ProgramData\\Microsoft\\Notepad.lnk", 1, 0x20, 1, 0);
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(4));
            write_k(t, "HKLM\\SOFTWARE\\Clients", 2, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Clients", "AppReg", 1, 4, 5, "x");
            write_k(t, "HKLM\\SOFTWARE\\Env", 2, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Env", "Path", 2, 4, 2, "C:\\Windows;C:\\Tools;C:\\App\\bin");
            write_k(t, "HKLM\\SOFTWARE\\Mozilla", 2, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Mozilla\\Firefox", 2, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Launcher", 2, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Churn", 2, Some(0), Some(0));
            write_k(t, &format!("HKU\\{SID}"), 1, Some(0), Some(1));
            write_k(t, &format!("HKU\\{SID}\\Software"), 1, Some(0), Some(1));
            write_k(t, &format!("HKU\\{SID}\\Software\\Mozilla"), 2, Some(0), Some(0));
            write_d(t, "C:\\ProgramData\\Microsoft", 0x10, 1, 0);
            write_f(t, "C:\\ProgramData\\Microsoft\\Notepad.lnk", 1, 0x20, 1, 0);
            write_d(t, "C:\\ProgramData\\Mozilla", 0x10, 2, 0);
            write_f(t, "C:\\ProgramData\\Mozilla\\x.dat", 2, 0x20, 1, 0);
            write_d(t, "C:\\Users\\t\\AppData\\Roaming\\Mozilla", 0x10, 2, 0);
            write_f(t, "C:\\Users\\t\\AppData\\Roaming\\Mozilla\\profiles.ini", 1, 0x20, 1, 0);
        });
        let k = |p: &str| Target::RegKey { path: p.into() };
        let idx = TruthIdx::new(
            vec![
                ti(k("HKLM\\SOFTWARE\\Mozilla"), "leftover"),
                ti(k("HKLM\\SOFTWARE\\Launcher"), "kept_owner"),
                ti(k("HKLM\\SOFTWARE\\Churn"), "ambient"),
                ti(k(&format!("HKU\\{SID}\\Software\\Mozilla")), "leftover"),
                ti(Target::RegValue { path: "HKLM\\SOFTWARE\\Clients".into(), name: "AppReg".into() }, "leftover"),
                ti(
                    Target::RegValueChanged {
                        path: "HKLM\\SOFTWARE\\Env".into(),
                        name: "Path".into(),
                        before: "C:\\Windows;C:\\Tools".into(),
                        after: "C:\\Windows;C:\\Tools;C:\\App\\bin".into(),
                    },
                    "leftover",
                ),
                ti(Target::Path { path: "C:\\ProgramData\\Mozilla".into() }, "leftover"),
                ti(Target::Path { path: "C:\\Users\\t\\AppData\\Roaming\\Mozilla".into() }, "user_data"),
            ],
            Some(SID),
        );
        (s0, s2, idx)
    }

    fn item(t: Target, band: &str, pre: bool) -> PlanItem {
        PlanItem { target: t, band: band.into(), preselected: pre, scanner: Some("S".into()), category: None }
    }

    #[test]
    fn package_offer_covers_its_deployment_state() {
        let pkg = "App_1.0.0.0_neutral__abc123";
        let roots = ["HKLM\\SOFTWARE", &format!("HKU\\{SID}_Classes"), "C:\\Program Files\\WindowsApps", "C:\\ProgramData"];
        let mapping = format!("HKU\\{SID}_Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings\\S-1-15-2-9");
        let s0 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(0));
            write_d(t, "C:\\Program Files\\WindowsApps", 0x10, 1, 0);
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StagingInfo\\App_1.0.0.0_neutral__abc123", 2, Some(0), Some(0));
            write_d(t, "C:\\Program Files\\WindowsApps", 0x10, 1, 0);
            write_d(t, "C:\\Program Files\\WindowsApps\\App_1.0.0.0_neutral__abc123", 0x10, 2, 0);
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
            write_d(t, "C:\\ProgramData\\Packages\\App_abc123", 0x10, 2, 0);
            write_k(t, &mapping, 2, Some(1), Some(0));
            write_v(t, &mapping, "Moniker", 1, 26, 9, "app_abc123");
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom\\ClassIndex\\{E6950302-61F0-4FEB-97DB-855E30D4A991}", 2, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\PackagedCom\\ClassIndex\\{E6950302-61F0-4FEB-97DB-855E30D4A991}\\App_1.0.0.0_neutral__abc123", 3, Some(0), Some(0));
        });
        let k = |p: &str| Target::RegKey { path: p.into() };
        let p = |x: &str| Target::Path { path: x.into() };
        let idx = TruthIdx::new(
            vec![
                ti(k("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StagingInfo\\App_1.0.0.0_neutral__abc123"), "leftover"),
                ti(p("C:\\Program Files\\WindowsApps\\App_1.0.0.0_neutral__abc123"), "leftover"),
                ti(p("C:\\ProgramData\\Packages\\App_abc123"), "leftover"),
                ti(k(&mapping), "leftover"),
                ti(k("HKLM\\SOFTWARE\\Classes\\PackagedCom\\ClassIndex\\{E6950302-61F0-4FEB-97DB-855E30D4A991}"), "leftover"),
                ti(p("C:\\ProgramData\\Other"), "leftover"),
            ],
            Some(SID),
        );
        // deny protects the deployment stores from raw deletes, not from the package API
        let deny = Deny::from_value(&json!(["^[PK]:.*(WindowsApps|StagingInfo|\\\\Packages\\\\)"]), Some(SID)).unwrap();
        let links = LinkMap::default();
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links };
        let plan = Plan {
            tool: "purge".into(),
            mode: "post".into(),
            items: vec![
                item(Target::AppxPackage { full_name: pkg.into() }, "Likely", false),
                item(p("C:\\ProgramData\\Packages\\App_abc123"), "Safe", true),
            ],
            ..Default::default()
        };
        let s = score_plan(&cx, "app", &plan, "p.json");
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["hit", "danger"]);
        assert_eq!(s.items[0].covers, 5);
        assert_eq!(s.covered_listed_nd, 5);
        assert_eq!(package_family(pkg).as_deref(), Some("App_abc123"));
        assert_eq!(package_family("NoUnderscores"), None);
    }

    #[test]
    fn segment_in_a_cut_preview_is_unknown() {
        let roots = ["HKLM\\SYSTEM"];
        let env = "HKLM\\SYSTEM\\Env";
        let long = format!("{};C:\\Tools", "a".repeat(crate::snap::PREVIEW_MAX - 5));
        let cut: String = long.chars().take(crate::snap::PREVIEW_MAX).collect();
        let s = snap_with_roots(&roots, |t| {
            write_k(t, env, 1, Some(2), Some(0));
            write_v(t, env, "Path", 2, 4000, 1, &cut);
            write_v(t, env, "Short", 2, 20, 2, "C:\\A;C:\\B");
        });
        let seg = |n: &str, s: &str| Target::RegMultiSzSegment { path: env.into(), name: n.into(), segment: s.into() };
        assert_eq!(exists(&s, &seg("Path", "C:\\Tools")), (false, false), "cut preview: unknown, never gone");
        assert_eq!(exists(&s, &seg("Short", "C:\\Z")), (false, true));
        assert_eq!(exists(&s, &seg("Short", "c:\\b\\")), (true, true));
    }

    #[test]
    fn depth1_child_values_are_unknown() {
        let s = snap_with_roots(&["HKLM\\SOFTWARE\\Vendor@1"], |t| {
            write_k(t, "HKLM\\SOFTWARE\\Vendor", 1, Some(1), Some(1));
            write_v(t, "HKLM\\SOFTWARE\\Vendor", "Y", 1, 4, 5, "y");
            write_k(t, "HKLM\\SOFTWARE\\Vendor\\Child", 1, Some(3), Some(0));
        });
        let v = |k: &str| Target::RegValue { path: k.into(), name: "X".into() };
        assert_eq!(exists(&s, &v("HKLM\\SOFTWARE\\Vendor\\Child")), (false, false));
        assert_eq!(exists(&s, &v("HKLM\\SOFTWARE\\Vendor")), (false, true));
    }

    #[test]
    fn absent_item_is_gone_not_danger() {
        let (s0, s2, idx) = fixture();
        let deny = Deny::from_value(&json!(["Notepad\\.lnk$", "Launcher"]), Some(SID)).unwrap();
        let links = LinkMap::default();
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links };
        let k = |p: &str| Target::RegKey { path: p.into() };
        let plan = Plan {
            tool: "old".into(),
            mode: "post".into(),
            items: vec![
                // inside kept_owner Launcher and matching deny, but absent from snap2: a no-op
                item(k("HKLM\\SOFTWARE\\Launcher\\OldVersion"), "Safe", true),
                // present kept_owner key: still danger
                item(k("HKLM\\SOFTWARE\\Launcher"), "Safe", true),
            ],
            ..Default::default()
        };
        let s = score_plan(&cx, "firefox", &plan, "p.json");
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["gone", "danger"]);
        assert_eq!(s.danger_listed, 1);
    }

    #[test]
    fn outcomes_and_metrics() {
        let (s0, s2, idx) = fixture();
        let deny = Deny::from_value(&json!(["Notepad\\.lnk$"]), Some(SID)).unwrap();
        let links = LinkMap::default();
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links };
        let k = |p: &str| Target::RegKey { path: p.into() };
        let p = |x: &str| Target::Path { path: x.into() };
        let plan = Plan {
            tool: "purge".into(),
            mode: "post".into(),
            items: vec![
                // covers (ancestor-free equal) via HKEY_LOCAL_MACHINE spelling
                item(k("HKEY_LOCAL_MACHINE\\SOFTWARE\\Mozilla"), "Safe", true),
                // HKCU maps to the run's SID
                item(k("HKEY_CURRENT_USER\\Software\\Mozilla"), "Likely", true),
                // partial: inside a leftover dir
                item(p("C:\\ProgramData\\Mozilla\\x.dat"), "Weak", false),
                // key danger: HKLM\SOFTWARE\Clients existed in snap0 (it holds a leftover value)
                item(k("HKLM\\SOFTWARE\\Clients"), "Safe", true),
                // value is fine: the value did not exist in snap0
                item(Target::RegValue { path: "HKLM\\SOFTWARE\\Clients".into(), name: "AppReg".into() }, "Safe", true),
                // value danger: Path existed in snap0
                item(Target::RegValue { path: "HKLM\\SOFTWARE\\Env".into(), name: "Path".into() }, "Safe", false),
                // segment covers the RegValueChanged
                item(
                    Target::RegMultiSzSegment {
                        path: "HKLM\\SOFTWARE\\Env".into(),
                        name: "Path".into(),
                        segment: "C:\\App\\bin\\".into(),
                    },
                    "Likely",
                    true,
                ),
                // kept_owner danger
                item(k("HKLM\\SOFTWARE\\Launcher"), "Safe", true),
                // ambient
                item(k("HKLM\\SOFTWARE\\Churn"), "Safe", true),
                // gone: never existed in snap2, inside a captured root
                item(p("C:\\ProgramData\\Gone"), "Safe", true),
                // deny example
                item(p("C:\\ProgramData\\Microsoft\\Notepad.lnk"), "Safe", true),
                // other: outside every captured root
                item(p("D:\\Elsewhere"), "Weak", false),
                // separator-aware: not an ancestor of Mozilla
                item(k("HKLM\\SOFTWARE\\Moz"), "Weak", false),
                // user data preselected
                item(p("C:\\Users\\t\\AppData\\Roaming\\Mozilla"), "Likely", true),
            ],
            ..Default::default()
        };
        let s = score_plan(&cx, "firefox", &plan, "p.json");
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(
            oc,
            vec![
                "hit", "hit", "hit", "danger", "hit", "danger", "hit", "danger", "ambient", "gone", "danger", "other", "gone",
                "hit"
            ]
        );
        assert!(s.items[3].reasons[0].starts_with("existed in snap0: K:HKLM\\SOFTWARE\\Clients"));
        assert!(s.items[7].reasons[0].starts_with("covers kept_owner"));
        assert!(s.items[10].reasons.iter().any(|r| r.starts_with("deny")));
        // truth: 5 leftover + 1 user_data
        assert_eq!(s.truth_n, 6);
        // covered: Mozilla, HKU Mozilla, AppReg (by key Clients and by value), Path changed (segment),
        // Roaming\Mozilla.  ProgramData\Mozilla only partial.
        assert_eq!(s.covered_listed, 5);
        assert_eq!(s.partial_n, 1);
        assert_eq!(s.recall_listed, Some(5.0 / 6.0));
        // visible = Safe or Likely: same five
        assert_eq!(s.covered_visible, 5);
        // safe: Mozilla, AppReg (Clients key + value)
        assert_eq!(s.covered_safe, 2);
        assert_eq!(s.danger_listed, 4);
        assert_eq!(s.danger_preselected, 3);
        assert_eq!(s.userdata_preselected, 1);
        // Safe items: Mozilla(hit) Clients(danger) AppReg(hit) Env|Path(danger) Launcher(danger) Churn(ambient)
        // Gone(gone) Notepad(danger) => 8 safe, 7 not gone, 2 hits
        assert_eq!((s.safe_n, s.safe_not_gone, s.safe_hits), (8, 7, 2));
        assert_eq!(s.per_kind["RegValueChanged"].covered, 1);
        assert_eq!(s.per_kind["Path"].n, 2);
        assert_eq!(s.missed.len(), 1);
        assert!(s.missed[0].partial);

        let apps = vec![AppScore { id: "firefox".into(), tools: vec![s.clone()], ..Default::default() }, AppScore {
            id: "b".into(),
            tools: vec![ToolScore { tool: "purge".into(), truth_n: 1, recall_listed: Some(0.0), ..Default::default() }],
            ..Default::default()
        }];
        let m = macro_scores(&apps);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].apps, 2);
        assert!((m[0].recall_listed.unwrap() - (5.0 / 6.0) / 2.0).abs() < 1e-9);
        let md = render_md(&apps, &m);
        assert!(md.contains("| purge | 2 |"));
        // non-danger recall: the Clients key (danger) adds nothing the AppReg value item did not
        assert_eq!((s.covered_listed_nd, s.covered_visible_nd, s.covered_safe_nd), (5, 5, 2));
    }

    fn score_one(s0: &Snap, s2: &Snap, truth: Vec<TruthItem>, offered: Vec<PlanItem>) -> ToolScore {
        let idx = TruthIdx::new(truth, Some(SID));
        let deny = Deny::default();
        let links = LinkMap::new(s0.reg_links().into_iter().chain(s2.reg_links()));
        let cx = Ctx { truth: &idx, s0, s2, deny: &deny, sid: Some(SID), links: &links };
        score_plan(&cx, "app", &Plan { tool: "t".into(), items: offered, ..Default::default() }, "p.json")
    }

    #[test]
    fn wow64_link_alias_is_danger_and_hit() {
        const CLSID: &str = "{AAAAAAAA-0000-0000-0000-000000000001}";
        let link = |t: &mut String| {
            write_k(t, "HKLM\\SOFTWARE\\WOW6432Node\\Classes", 1, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\WOW6432Node\\Classes", "SymbolicLinkValue", 6, 92, 1, "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Wow6432Node");
            // a link that canon_reg does not know: resolved through the snap's own link records
            write_k(t, "HKLM\\SOFTWARE\\OddLink", 1, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\OddLink", "SymbolicLinkValue", 6, 40, 2, "\\REGISTRY\\MACHINE\\SOFTWARE\\Real");
        };
        let s0 = snap_with_roots(&["HKLM\\SOFTWARE"], |t| {
            link(t);
            write_k(t, &format!("HKLM\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{CLSID}"), 1, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Real\\Pre", 1, Some(0), Some(0));
        });
        let s2 = snap_with_roots(&["HKLM\\SOFTWARE"], |t| {
            link(t);
            write_k(t, &format!("HKLM\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{CLSID}"), 1, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Real\\Pre", 1, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Clients\\StartMenuInternet\\Firefox-1", 2, Some(0), Some(0));
        });
        let truth = vec![ti(Target::RegKey { path: "HKLM\\SOFTWARE\\Clients\\StartMenuInternet\\Firefox-1".into() }, "leftover")];
        let k = |p: &str| Target::RegKey { path: p.into() };
        let s = score_one(
            &s0,
            &s2,
            truth,
            vec![
                item(k(&format!("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Classes\\CLSID\\{CLSID}")), "Safe", true),
                item(k("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet\\Firefox-1"), "Safe", true),
                item(k("HKLM\\SOFTWARE\\OddLink\\Pre"), "Safe", true),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["danger", "hit", "danger"]);
        assert_eq!(s.items[0].target, format!("K:HKLM\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{CLSID}"));
        assert_eq!(s.items[2].target, "K:HKLM\\SOFTWARE\\Real\\Pre");
        assert_eq!(s.recall_listed, Some(1.0));
    }

    #[test]
    fn default_hive_aliases() {
        // An older snap that followed HKU\S-1-5-18 holds .DEFAULT twice; the loader drops the alias copy.
        let roots = ["HKU\\.DEFAULT", "HKU\\S-1-5-18"];
        let body = |t: &mut String, app: bool| {
            for h in ["HKU\\.DEFAULT", "HKU\\S-1-5-18"] {
                write_k(t, h, 1, Some(0), Some(1));
                write_k(t, &format!("{h}\\Software"), 1, Some(0), Some(1));
                write_k(t, &format!("{h}\\Software\\Classes"), 1, Some(0), Some(1));
                write_k(t, &format!("{h}\\Software\\Classes\\Foo"), 1, Some(0), Some(0));
                if app {
                    write_k(t, &format!("{h}\\Software\\App"), 2, Some(0), Some(0));
                }
            }
        };
        let s0 = snap_with_roots(&roots, |t| body(t, false));
        let s2 = snap_with_roots(&roots, |t| body(t, true));
        assert!(s0.alias_dropped > 0);
        let derived = crate::items::derive(&s0, &s2);
        let cs: Vec<String> = derived.iter().map(|i| i.target.canon_string()).collect();
        assert_eq!(cs, vec!["K:HKU\\.DEFAULT\\Software\\App"]);
        let truth: Vec<TruthItem> = derived.into_iter().map(|i| ti(i.target, "leftover")).collect();
        let k = |p: &str| Target::RegKey { path: p.into() };
        let s = score_one(
            &s0,
            &s2,
            truth,
            vec![
                // the alias spelling of the leftover
                item(k("HKEY_USERS\\S-1-5-18\\Software\\App"), "Safe", true),
                // a real, pre-existing key under .DEFAULT\Software\Classes (no _Classes rewrite)
                item(k("HKU\\.DEFAULT\\Software\\Classes\\Foo"), "Safe", true),
                item(k("HKU\\S-1-5-18\\Software\\Classes\\Foo"), "Safe", true),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["hit", "danger", "danger"]);
        assert_eq!(s.recall_listed, Some(1.0));
    }

    #[test]
    fn danger_item_earns_no_nondanger_recall() {
        let roots = ["C:\\Users"];
        let s0 = snap_with_roots(&roots, |t| {
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\AppData", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\AppData\\Local", 0x10, 1, 0);
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\AppData", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\AppData\\Local", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\AppData\\Local\\App", 0x10, 2, 0);
        });
        let truth = vec![ti(Target::Path { path: "C:\\Users\\t\\AppData\\Local\\App".into() }, "leftover")];
        let s = score_one(&s0, &s2, truth, vec![item(Target::Path { path: "C:\\Users\\t".into() }, "Safe", true)]);
        assert_eq!(s.items[0].outcome, "danger");
        // RIG §7 recall (any covering item) vs. recall from non-danger items only
        assert_eq!(s.recall_safe, Some(1.0));
        assert_eq!(s.recall_safe_nd, Some(0.0));
        assert_eq!(s.recall_listed_nd, Some(0.0));
    }

    #[test]
    fn unreadable_subtree_is_not_gone() {
        let body = |t: &mut String| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Locked", 1, None, None);
            write_k(t, "HKLM\\SOFTWARE\\Partial", 1, Some(0), Some(3));
            t.push_str(&crate::snap::meta_line("denied", &["HKLM\\SOFTWARE\\Partial".into()]));
            write_k(t, "HKLM\\SOFTWARE\\Open", 1, Some(0), Some(0));
            write_d(t, "C:\\ProgramData\\Denied", 0x10, 1, 0);
            t.push_str(&crate::snap::meta_line("denied", &["C:\\ProgramData\\Denied".into()]));
        };
        let roots = ["HKLM\\SOFTWARE", "C:\\ProgramData"];
        let s0 = snap_with_roots(&roots, body);
        let s2 = snap_with_roots(&roots, body);
        assert!(!s2.captures_key("HKLM\\SOFTWARE\\Locked\\Sub"));
        assert!(!s2.captures_key("HKLM\\SOFTWARE\\Partial\\Sub\\x"));
        assert!(s2.captures_key("HKLM\\SOFTWARE\\Open\\Sub"));
        assert!(!s2.captures_path("C:\\ProgramData\\Denied\\x"));
        assert!(s2.captures_path("C:\\ProgramData\\Other\\x"));
        let k = |p: &str| Target::RegKey { path: p.into() };
        let s = score_one(
            &s0,
            &s2,
            vec![],
            vec![
                item(k("HKLM\\SOFTWARE\\Locked\\Sub"), "Safe", true),
                item(Target::Path { path: "C:\\ProgramData\\Denied\\x".into() }, "Safe", true),
                item(Target::RegValue { path: "HKLM\\SOFTWARE\\Partial".into(), name: "v".into() }, "Safe", true),
                item(k("HKLM\\SOFTWARE\\Open\\Sub"), "Safe", true),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["other", "other", "other", "gone"]);
        // unknown items stay in the precision denominator
        assert_eq!((s.safe_n, s.safe_not_gone), (4, 3));
    }

    #[test]
    fn kept_container_split_scores_danger() {
        use crate::truth::{KeptAnchors, Labeler, kept_entries, label_items, split_kept};
        let pk = "2CA138371E0F3714F9BD0D47367DBE08";
        let inst = "HKLM\\SOFTWARE\\Classes\\Installer";
        let roots = ["HKLM\\SOFTWARE"];
        let s0 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes", 1, Some(0), Some(0));
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes", 1, Some(0), Some(1));
            write_k(t, inst, 2, Some(1), Some(2));
            write_v(t, inst, "Marker", 1, 4, 3, "x");
            write_k(t, &format!("{inst}\\Products"), 2, Some(0), Some(2));
            write_k(t, &format!("{inst}\\Products\\{pk}"), 2, Some(1), Some(1));
            write_v(t, &format!("{inst}\\Products\\{pk}"), "ProductName", 1, 4, 4, "Launcher");
            write_k(t, &format!("{inst}\\Products\\{pk}\\SourceList"), 2, Some(0), Some(0));
            write_k(t, &format!("{inst}\\Products\\FFFF0000FFFF0000FFFF0000FFFF0000"), 2, Some(0), Some(0));
            write_k(t, &format!("{inst}\\Features"), 2, Some(0), Some(1));
            write_k(t, &format!("{inst}\\Features\\FFFF0000FFFF0000FFFF0000FFFF0000"), 2, Some(0), Some(0));
        });
        let run = json!({"entries_left": [{
            "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{73831AC2-F0E1-4173-9FDB-D07463D7EB80}",
            "name": "Launcher", "msi": "{73831AC2-F0E1-4173-9FDB-D07463D7EB80}"
        }]});
        let entries = kept_entries(&run, &json!({"uninstall": []}), &json!({"uninstall": []}), Some(SID));
        let lab = Labeler {
            rig: crate::items::RigRules::new(&[]),
            ambient: None,
            rules: vec![],
            kept: KeptAnchors::from_entries(&entries, Some(SID)),
        };
        let derived = crate::items::derive(&s0, &s2);
        assert_eq!(derived.len(), 1);
        let (split, n) = split_kept(derived, &s0, &s2, &lab);
        assert_eq!(n, 1);
        let truth = label_items(split, &lab, None);
        let got: Vec<(String, &str)> = truth.iter().map(|i| (i.target.canon_string(), i.label.as_str())).collect();
        assert_eq!(
            got,
            vec![
                (format!("K:{inst}\\Features"), "leftover"),
                (format!("K:{inst}\\Products\\{pk}"), "kept_owner"),
                (format!("K:{inst}\\Products\\FFFF0000FFFF0000FFFF0000FFFF0000"), "leftover"),
                (format!("V:{inst}|Marker"), "leftover"),
            ]
        );
        let k = |p: &str| Target::RegKey { path: p.into() };
        let s = score_one(
            &s0,
            &s2,
            truth,
            vec![
                item(k(inst), "Safe", true),
                item(k(&format!("{inst}\\Products\\{pk}")), "Safe", true),
                item(k(&format!("{inst}\\Products")), "Safe", true),
                item(k(&format!("{inst}\\Products\\FFFF0000FFFF0000FFFF0000FFFF0000")), "Safe", true),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["danger", "danger", "danger", "hit"]);
    }
}
