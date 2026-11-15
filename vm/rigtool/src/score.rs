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
    /// What executing the item does (Purge plans: `DeleteKey`, `DeleteValue`, `Quarantine`, `RemoveDirIfEmpty`,
    /// `RemovePackage`, ...). Absent = a delete (old tools). `RemoveDirIfEmpty` is scored by [`score_plan`]'s
    /// second pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub outcome: String,
    pub covers: usize,
    pub partial: usize,
    /// `noop_if_nonempty` items only: a plain delete of the target would have scored `danger`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub would_be_danger: bool,
    /// `--classes` only, danger items: `blocking` (Safe or preselected), `unticked` (listed, neither), or one of
    /// the separately reported kinds `preexisting_value_ref` / `old_empty_ext_key` / `replaced_value` (see
    /// [`danger_class`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// `--classes` only, items covering or inside a `user_data` truth item: `blocking` (Safe or preselected) or
    /// `unticked`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userdata: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Reporting classes of one plan (`--classes`, RIG.md §7). Every danger item is in exactly one of the four
/// danger classes; none is hidden, the classes only label them.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Classes {
    /// (1) gate-blocking: danger items offered Safe or preselected (not of a kind in (3)).
    pub danger_blocking: usize,
    /// (1) gate-blocking: Safe or preselected items covering or inside a user_data item (planted user files).
    pub userdata_blocking: usize,
    /// (2) reported, not blocking: the same, listed but unticked (Likely/Weak/Blocked, not preselected).
    pub danger_unticked: usize,
    pub userdata_unticked: usize,
    /// (3) reported in their own list (any band; band and preselection are shown): a value (or list segment) that
    /// existed in snap0, is unchanged in snap2, and whose data names a path that is absent in snap2: a dangling
    /// reference in a value the user or another product created.
    pub preexisting_value_ref: usize,
    /// (3) an `.ext` key (or its OpenWithProgids/OpenWithList subkey) of a Classes root that existed in snap0 and
    /// held no value anywhere below it then: an old empty extension key.
    pub old_empty_ext_key: usize,
    /// (3) a value that existed in snap0 under the same name and whose data changed by snap2 (Windows or the app
    /// overwrote the slot with the app's record, e.g. `UFH\SHC|<n>`): unticked only. Deleting it removes the
    /// app's record and cannot bring the old data back, so it stays a hand review; Safe or preselected it is
    /// `blocking`.
    pub replaced_value: usize,
    /// G9: Safe items covering or inside a user_data item, preselected or not.
    pub userdata_safe: usize,
}

impl Classes {
    fn add(&mut self, o: &Classes) {
        self.danger_blocking += o.danger_blocking;
        self.userdata_blocking += o.userdata_blocking;
        self.danger_unticked += o.danger_unticked;
        self.userdata_unticked += o.userdata_unticked;
        self.preexisting_value_ref += o.preexisting_value_ref;
        self.old_empty_ext_key += o.old_empty_ext_key;
        self.replaced_value += o.replaced_value;
        self.userdata_safe += o.userdata_safe;
    }
}

/// The path a registry value's data names, as far as a simple reading goes: the quoted part of a quoted command,
/// else the data up to and including the first `.exe`, else the whole data (trailing `\` removed); environment
/// variables expanded. `None` when the data does not start with a drive-letter path.
fn data_path(data: &str) -> Option<String> {
    let d = data.trim();
    let p = if let Some(rest) = d.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else if let Some(i) = d.to_ascii_lowercase().find(".exe") {
        d[..i + 4].to_string()
    } else {
        d.to_string()
    };
    let p = snap::expand_env(p.trim()).trim_end_matches('\\').to_string();
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then_some(p)
}

/// Does `path` (from a value's data) dangle in snap2: absent there although the capture covers it?
fn dangles(s2: &Snap, path: &str) -> bool {
    let p = canon::canon_path(path);
    !s2.has_path(&p) && s2.captures_path(&p)
}

/// The class of a danger item (RIG.md §7 reporting classes).
fn danger_class(cx: &Ctx, o: &Target, reasons: &[String], band: Band, preselected: bool) -> &'static str {
    let only_snap0 = !reasons.is_empty() && reasons.iter().all(|r| r.starts_with("existed in snap0"));
    if only_snap0 {
        match o {
            Target::RegValue { path, name } => {
                if let (Some(a), Some(b)) = (cx.s0.value(path, name), cx.s2.value(path, name)) {
                    if a.hash == b.hash && matches!(a.typ, 1 | 2 | 7) && data_path(&a.preview).is_some_and(|p| dangles(cx.s2, &p)) {
                        return "preexisting_value_ref";
                    }
                    if a.hash != b.hash && band != Band::Safe && !preselected {
                        return "replaced_value";
                    }
                }
            }
            Target::RegMultiSzSegment { path, name, segment } => {
                if let (Some(a), Some(b)) = (cx.s0.value(path, name), cx.s2.value(path, name))
                    && a.hash == b.hash
                    && data_path(segment).is_some_and(|p| dangles(cx.s2, &p))
                {
                    return "preexisting_value_ref";
                }
            }
            Target::RegKey { path } => {
                let f = canon::fold(path);
                let ext = regex::Regex::new(r"(?i)^(hklm\\software\\classes|hku\\[^\\]+_classes)\\\.[^\\]+(\\(openwithprogids|openwithlist))?$")
                    .expect("ext regex");
                if ext.is_match(&f)
                    && cx.s0.has_key(path)
                    && !cx
                        .s0
                        .keys
                        .iter()
                        .any(|(k, r)| canon::is_under_or_eq_folded(&canon::fold(k.as_str()), &f) && !r.values.is_empty())
                {
                    return "old_empty_ext_key";
                }
            }
            _ => {}
        }
    }
    if band == Band::Safe || preselected { "blocking" } else { "unticked" }
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
    /// Every listed item whose outcome is `danger`, the read-only Blocked list included (the number reported as
    /// "danger" before 2026-11-15).
    pub danger_listed: usize,
    /// Danger items offered for removal: listed in any band but Blocked. This is "danger" in the reports.
    pub danger_offered: usize,
    /// Danger items the engine lists read-only as Blocked (kept): shown, never removable.
    pub danger_kept: usize,
    /// Danger items offered Safe or preselected, except the reporting kinds that never block when unticked
    /// (RIG.md §7 class (1); computed with or without `--classes`). The gate counts this one.
    pub danger_blocking: usize,
    pub danger_preselected: usize,
    pub userdata_preselected: usize,
    /// Delete-if-empty items that stay (outcome `noop_if_nonempty`), and how many of them a plain delete
    /// would have made danger. Reported next to danger, not inside it.
    pub noop_if_nonempty: usize,
    pub noop_would_be_danger: usize,
    /// The run's snap0 holds an earlier install of the same product (run.json `pre` entry with the run's own ARP
    /// key, removed before snap0): the clean run whose snap0 / lists-0 decided "existed before" instead, and the
    /// offered targets that existed in this run's snap0 only through that earlier install (not danger).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_same_app_base: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pre_same_app_excused: Vec<String>,
    /// `--classes` only (RIG.md §7 reporting classes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes: Option<Classes>,
    pub outcomes: BTreeMap<String, usize>,
    pub per_kind: BTreeMap<String, KindRecall>,
    pub per_scanner: BTreeMap<String, BTreeMap<String, usize>>,
    pub missed: Vec<Missed>,
    pub danger: Vec<ItemOutcome>,
    pub noop: Vec<ItemOutcome>,
    pub items: Vec<ItemOutcome>,
}

fn ratio(a: usize, b: usize) -> Option<f64> {
    if b == 0 { None } else { Some(a as f64 / b as f64) }
}

pub const OUTCOMES: [&str; 6] = ["danger", "hit", "ambient", "gone", "noop_if_nonempty", "other"];
const KINDS: [&str; 4] = ["Path", "RegKey", "RegValue", "RegValueChanged"];

pub struct Ctx<'a> {
    pub truth: &'a TruthIdx,
    pub s0: &'a Snap,
    pub s2: &'a Snap,
    pub deny: &'a Deny,
    pub sid: Option<&'a str>,
    /// Registry links recorded in snap0/snap2 (beyond the ones `canon_reg` folds itself).
    pub links: &'a LinkMap,
    /// The system objects of lists-0 (packages, tasks, services, firewall rules), when the run has one.
    pub lists0: Option<&'a ListIdx>,
    /// Report the reporting classes (`--classes`, RIG.md §7): off by default so older reports stay byte-identical.
    pub classes: bool,
    /// Set when snap0 holds an earlier install of the same product (see [`PreBase`]).
    pub pre_base: Option<&'a PreBase>,
}

/// A clean reference for a run whose snap0 already holds an earlier install (and removal) of the same product
/// (ff-reinstall): a primitive that is in this run's snap0 does not count as "existed before" when it is absent
/// from the reference's snap0 and was last written (file mtime, key last-write time) at or after the earlier
/// install started (`since`). Lists-0 objects the same way, without the time test (lists carry no times). The reference is another run of the same campaign without a pre-app,
/// restored from the same snapshot on the same machine.
pub struct PreBase {
    pub run: String,
    pub s0: Snap,
    pub lists0: Option<ListIdx>,
    /// FILETIME (UTC, 100 ns since 1601) of the earlier install's start, less two minutes.
    pub since: u64,
}

impl PreBase {
    /// Did primitive `p` (present in `s0`, this run's snap0) come from the earlier install of the same product?
    fn from_earlier_install(&self, s0: &Snap, p: &Target) -> bool {
        if exists(&self.s0, p).0 {
            return false;
        }
        let t = match p {
            Target::Path { path } => s0.path(path).map(|r| r.mtime),
            Target::RegKey { path } | Target::RegValue { path, .. } | Target::RegMultiSzSegment { path, .. } => {
                s0.key(path).map(|r| r.lwt)
            }
            _ => None,
        };
        t.is_some_and(|t| t >= self.since)
    }
}

/// FILETIME (100 ns since 1601-01-01 UTC) of an ISO 8601 time with offset, as run.json writes them
/// (`2026-11-15T05:17:05.9420226+03:00`). `None` when it does not parse.
pub fn iso_filetime(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let tz_at = rest.rfind(['+', '-']).filter(|&i| i >= 8);
    let (time, off) = match (tz_at, rest.strip_suffix('Z')) {
        (_, Some(t)) => (t, 0i64),
        (Some(i), None) => {
            let (h, m) = rest[i + 1..].split_once(':')?;
            let o = h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60;
            (&rest[..i], if &rest[i..i + 1] == "-" { -o } else { o })
        }
        (None, None) => (rest, 0),
    };
    let mut t = time.split(':');
    let (h, mi) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let sec: f64 = t.next()?.parse().ok()?;
    // days from civil (proleptic Gregorian), Howard Hinnant's algorithm
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let unix = days * 86400 + h * 3600 + mi * 60 - off;
    let ft = (unix + 11_644_473_600) as f64 * 1e7 + sec * 1e7;
    (ft > 0.0).then_some(ft as u64)
}

/// System objects present in a run's lists-0 (RIG.md §3), for the kinds a snapshot cannot show directly: an
/// `AppxPackage` (a sparse package has no folder under WindowsApps, and WindowsApps itself is not readable), and
/// `Task` / `Service` / `FirewallRule` (also seen through their registry/file primitives; the list is the
/// authoritative "it existed before" for them). An offer of one of these that was present in lists-0 is `danger`,
/// also when it is gone by lists-2.
#[derive(Default, Debug)]
pub struct ListIdx {
    appx: std::collections::HashSet<String>,
    tasks: std::collections::HashSet<String>,
    services: std::collections::HashSet<String>,
    firewall: std::collections::HashSet<String>,
}

impl ListIdx {
    pub fn from_value(v: &serde_json::Value) -> ListIdx {
        let set = |sec: &str, field: &str, norm: &dyn Fn(&str) -> String| -> std::collections::HashSet<String> {
            v.get(sec)
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|e| e.get(field).and_then(|s| s.as_str())).map(norm).collect())
                .unwrap_or_default()
        };
        let plain = |s: &str| canon::fold(s.trim());
        let task = |s: &str| canon::fold(&format!("\\{}", s.trim().trim_start_matches('\\').trim_end_matches('\\')));
        ListIdx {
            appx: set("appx", "full_name", &plain),
            tasks: set("tasks", "path", &task),
            services: set("services", "name", &plain),
            firewall: set("firewall", "id", &plain),
        }
    }

    pub fn load(p: &Path) -> Result<ListIdx> {
        let v: serde_json::Value = jsonio::read(p)?;
        Ok(ListIdx::from_value(&v))
    }

    /// Is the (canonical) target a system object listed in lists-0?
    pub fn has(&self, o: &Target) -> bool {
        match o {
            Target::AppxPackage { full_name } => self.appx.contains(&canon::fold(full_name)),
            Target::Task { path } => self.tasks.contains(&canon::fold(path)),
            Target::Service { name } => self.services.contains(&canon::fold(name)),
            Target::FirewallRule { id } => self.firewall.contains(&canon::fold(id)),
            _ => false,
        }
    }
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

/// Does a plan action remove its target only when it is empty at its turn (`RemoveDirIfEmpty`)?
pub fn is_if_empty(action: Option<&str>) -> bool {
    action.is_some_and(|a| a.to_ascii_lowercase().ends_with("ifempty"))
}

/// Does a plan action take its target away? `None` (plans without actions: the old tools, older Purge
/// plans) counts as a delete, as before. A segment edit or a report-only item removes nothing.
fn removes(action: Option<&str>) -> bool {
    match action.map(|a| a.to_ascii_lowercase()) {
        None => true,
        Some(a) => !matches!(a.as_str(), "editsegment" | "reportonly"),
    }
}

/// What the plan's non-danger removals take away (the counterfactual of an accepted plan: the gate requires
/// danger 0, so a danger item is treated as not executed).
#[derive(Default)]
struct Removed {
    paths: Vec<String>,
    keys: Vec<String>,
    values: std::collections::HashSet<String>,
}

impl Removed {
    fn add(&mut self, t: &Target) {
        match t {
            Target::Path { path } => self.paths.push(canon::fold(path)),
            Target::RegKey { path } => self.keys.push(canon::fold(path)),
            Target::RegValue { path, name } => {
                self.values.insert(canon::fold(&format!("{path}|{name}")));
            }
            _ => {}
        }
    }
    fn path(&self, p: &str) -> bool {
        let f = canon::fold(p);
        self.paths.iter().any(|r| canon::is_under_or_eq_folded(&f, r))
    }
    fn key(&self, k: &str) -> bool {
        let f = canon::fold(k);
        self.keys.iter().any(|r| canon::is_under_or_eq_folded(&f, r))
    }
    fn value(&self, k: &str, name: &str) -> bool {
        self.key(k) || self.values.contains(&canon::fold(&format!("{k}|{name}")))
    }
}

/// What is still inside `o` (a dir or key, in snap2) once the plan's other removals ran: (count, how many
/// of those existed in snap0, up to 3 examples).
fn remaining_inside(s0: &Snap, s2: &Snap, o: &Target, rem: &Removed) -> (usize, usize, Vec<String>) {
    let (mut n, mut pre, mut ex) = (0usize, 0usize, Vec::new());
    let mut note = |cs: String, existed: bool| {
        n += 1;
        if existed {
            pre += 1;
        }
        if ex.len() < 3 {
            ex.push(cs);
        }
    };
    match o {
        Target::Path { path } => {
            let a = canon::fold(path);
            let mut kids: Vec<&str> = s2
                .fs
                .keys()
                .map(|k| k.as_str())
                .filter(|k| {
                    let f = canon::fold(k);
                    f.len() != a.len() && canon::is_under_or_eq_folded(&f, &a)
                })
                .collect();
            kids.sort_by(|x, y| canon::ci_cmp(x, y));
            for k in kids {
                // As the engine's emptiness rule (purge-plan empty_after.rs): desktop.ini and Thumbs.db do not
                // keep a folder from being empty.
                let leaf = k.rsplit('\\').next().unwrap_or("");
                if leaf.eq_ignore_ascii_case("desktop.ini") || leaf.eq_ignore_ascii_case("Thumbs.db") {
                    continue;
                }
                if !rem.path(k) {
                    note(format!("P:{k}"), s0.has_path(k));
                }
            }
        }
        Target::RegKey { path } => {
            let a = canon::fold(path);
            let mut keys: Vec<&str> = s2
                .keys
                .keys()
                .map(|k| k.as_str())
                .filter(|k| canon::is_under_or_eq_folded(&canon::fold(k), &a))
                .collect();
            keys.sort_by(|x, y| canon::ci_cmp(x, y));
            for k in keys {
                let strictly = canon::fold(k).len() != a.len();
                if strictly && !rem.key(k) && s2.key(k).is_some_and(|r| r.seen) {
                    note(format!("K:{k}"), s0.has_key(k));
                }
                if let Some(kr) = s2.key(k) {
                    for v in &kr.values {
                        if !rem.value(k, &v.name) {
                            note(format!("V:{k}|{}", v.name), s0.value(k, &v.name).is_some());
                        }
                    }
                }
            }
        }
        _ => {}
    }
    (n, pre, ex)
}

/// One offered item, evaluated as if it were executed on its own (pass 1 of [`score_plan`]).
struct Eval {
    o: Target,
    prims: Vec<Target>,
    all_gone: bool,
    covers: BTreeSet<usize>,
    partial: BTreeSet<usize>,
    reasons: Vec<String>,
    outcome: &'static str,
    if_empty: bool,
    /// `noop_if_nonempty` only: the item would have been `danger` as a plain delete.
    would_be_danger: bool,
    /// Primitives in snap0 (or lists-0) only through an earlier install of the same product ([`PreBase`]).
    excused: Vec<String>,
}

fn eval_item(cx: &Ctx, it: &PlanItem) -> Eval {
    let t = cx.truth;
    // Canonical spelling, then any registry link the snaps recorded (an offered alias path matches
    // the data the capture holds under the link's target).
    let o = it.target.canonical(cx.sid).map_reg(|k| cx.links.resolve(k));
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
    let mut reasons = Vec::new();
    let mut excused = Vec::new();
    for p in prims.iter().filter(|_| !all_gone) {
        if exists(cx.s0, p).0 {
            if cx.pre_base.is_some_and(|b| b.from_earlier_install(cx.s0, p)) {
                excused.push(p.canon_string());
            } else {
                reasons.push(format!("existed in snap0: {}", p.canon_string()));
            }
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
    // System objects (packages, tasks, services, firewall rules) that lists-0 holds existed before the install,
    // whatever their primitives show (G6; a sparse package has no folder a snapshot could see).
    if let Some(l) = cx.lists0
        && l.has(&o)
    {
        if cx.pre_base.is_some_and(|b| b.lists0.as_ref().is_some_and(|l0| !l0.has(&o))) {
            excused.push(o.canon_string());
        } else {
            reasons.push(format!("existed in lists-0: {}", o.canon_string()));
        }
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
    Eval {
        o,
        prims,
        all_gone,
        covers,
        partial,
        reasons,
        outcome,
        if_empty: is_if_empty(it.action.as_deref()),
        would_be_danger: false,
        excused,
    }
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
    if cx.classes {
        sc.classes = Some(Classes::default());
    }

    // Pass 1: every item on its own.
    let mut evals: Vec<Eval> = plan.items.iter().map(|it| eval_item(cx, it)).collect();

    // Pass 2: delete-if-empty items (RIG.md §7). Such an item removes its dir or key only when nothing is left
    // inside once the plan's other removals ran; then it is scored like a delete. Otherwise it is a no-op:
    // outcome `noop_if_nonempty`, no coverage, and listed separately (with `would_be_danger` when a plain
    // delete of it would have scored danger), never silently dropped. Deepest first, so an inner container
    // that empties counts as removed for its parent. "The plan's other removals" = every offered item that is
    // not gone and not danger, whatever its band or preselection (the plan as accepted in full); a key holding
    // a value is not empty (purge-plan empty_after.rs: a key's children are its subkeys and values).
    let mut rem = Removed::default();
    for (e, it) in evals.iter().zip(&plan.items) {
        if e.if_empty || e.all_gone || e.outcome == "danger" || !removes(it.action.as_deref()) {
            continue;
        }
        for p in &e.prims {
            rem.add(p);
        }
        if let Target::AppxPackage { full_name } = &e.o {
            for i in package_covers(t, full_name, cx.s2) {
                rem.add(&t.items[i].target);
            }
        }
    }
    let mut order: Vec<usize> = (0..evals.len()).filter(|&i| evals[i].if_empty && !evals[i].all_gone).collect();
    let depth = |e: &Eval| e.o.canon_string().matches('\\').count();
    order.sort_by_key(|&i| std::cmp::Reverse(depth(&evals[i])));
    for i in order {
        let (n, pre, ex) = remaining_inside(cx.s0, cx.s2, &evals[i].o, &rem);
        let e = &mut evals[i];
        if n == 0 {
            if e.outcome != "danger" {
                for p in &e.prims {
                    rem.add(p);
                }
            }
            continue;
        }
        let mut why = vec![format!(
            "not empty after the plan's other removals: {n} entr{} left inside ({pre} existed in snap0), e.g. {}",
            if n == 1 { "y" } else { "ies" },
            ex.join(", ")
        )];
        e.would_be_danger = e.outcome == "danger";
        if e.would_be_danger {
            why.extend(e.reasons.iter().map(|r| format!("as a plain delete: {r}")));
        }
        e.reasons = why;
        e.outcome = "noop_if_nonempty";
        e.covers.clear();
        e.partial.clear();
    }

    let n = t.items.len();
    let mut cov_any = vec![false; n];
    let mut cov_vis = vec![false; n];
    let mut cov_safe = vec![false; n];
    let mut cov_any_nd = vec![false; n];
    let mut cov_vis_nd = vec![false; n];
    let mut cov_safe_nd = vec![false; n];
    let mut part_any = vec![false; n];

    sc.pre_same_app_base = cx.pre_base.map(|b| b.run.clone());
    for (e, it) in evals.into_iter().zip(&plan.items) {
        let band = band_of(&it.band);
        let outcome = e.outcome;
        if !e.excused.is_empty() && outcome != "danger" {
            sc.pre_same_app_excused.push(e.o.canon_string());
        }
        for &i in &e.partial {
            part_any[i] = true;
        }
        let visible = matches!(band, Band::Safe | Band::Likely);
        for &i in &e.covers {
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
            // A no-op (gone, or a delete-if-empty that stays) neither helps nor harms precision.
            if outcome != "gone" && outcome != "noop_if_nonempty" {
                sc.safe_not_gone += 1;
            }
            if outcome == "hit" {
                sc.safe_hits += 1;
            }
        }
        let touches_ud = e.covers.iter().chain(e.partial.iter()).any(|&i| t.items[i].label == "user_data");
        if it.preselected && touches_ud {
            sc.userdata_preselected += 1;
        }
        let (mut class, mut userdata) = (None, None);
        let dclass = (outcome == "danger").then(|| danger_class(cx, &e.o, &e.reasons, band, it.preselected));
        if dclass == Some("blocking") {
            sc.danger_blocking += 1;
        }
        if cx.classes {
            let c = sc.classes.get_or_insert_with(Classes::default);
            let ticked = band == Band::Safe || it.preselected;
            if let Some(k) = dclass {
                match k {
                    "blocking" => c.danger_blocking += 1,
                    "unticked" => c.danger_unticked += 1,
                    "preexisting_value_ref" => c.preexisting_value_ref += 1,
                    "replaced_value" => c.replaced_value += 1,
                    _ => c.old_empty_ext_key += 1,
                }
                class = Some(k.to_string());
            }
            if touches_ud {
                if ticked {
                    c.userdata_blocking += 1;
                } else {
                    c.userdata_unticked += 1;
                }
                if band == Band::Safe {
                    c.userdata_safe += 1;
                }
                userdata = Some(if ticked { "blocking" } else { "unticked" }.to_string());
            }
        }
        let mut reasons = e.reasons;
        if dclass == Some("replaced_value")
            && let Target::RegValue { path, name } = &e.o
            && let (Some(a), Some(b)) = (cx.s0.value(path, name), cx.s2.value(path, name))
        {
            let cut = |s: &str| s.chars().take(160).collect::<String>().replace('\0', " | ");
            reasons.push(format!("replaced: before `{}`, after `{}`", cut(&a.preview), cut(&b.preview)));
        }
        let io = ItemOutcome {
            target: e.o.canon_string(),
            band: it.band.clone(),
            preselected: it.preselected,
            scanner: it.scanner.clone(),
            action: it.action.clone(),
            outcome: outcome.to_string(),
            covers: e.covers.len(),
            partial: e.partial.len(),
            would_be_danger: e.would_be_danger,
            class,
            userdata,
            reasons,
        };
        if outcome == "danger" {
            sc.danger_listed += 1;
            if band == Band::Blocked {
                sc.danger_kept += 1;
            } else {
                sc.danger_offered += 1;
            }
            if it.preselected {
                sc.danger_preselected += 1;
            }
            sc.danger.push(io.clone());
        }
        if outcome == "noop_if_nonempty" {
            sc.noop_if_nonempty += 1;
            if io.would_be_danger {
                sc.noop_would_be_danger += 1;
            }
            sc.noop.push(io.clone());
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
    pub danger_offered: usize,
    pub danger_kept: usize,
    pub danger_blocking: usize,
    pub danger_preselected: usize,
    pub userdata_preselected: usize,
    pub noop_if_nonempty: usize,
    pub noop_would_be_danger: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes: Option<Classes>,
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
                danger_offered: v.iter().map(|t| t.danger_offered).sum(),
                danger_kept: v.iter().map(|t| t.danger_kept).sum(),
                danger_blocking: v.iter().map(|t| t.danger_blocking).sum(),
                danger_preselected: v.iter().map(|t| t.danger_preselected).sum(),
                userdata_preselected: v.iter().map(|t| t.userdata_preselected).sum(),
                noop_if_nonempty: v.iter().map(|t| t.noop_if_nonempty).sum(),
                noop_would_be_danger: v.iter().map(|t| t.noop_would_be_danger).sum(),
                classes: v.iter().filter_map(|t| t.classes.as_ref()).fold(None, |acc: Option<Classes>, c| {
                    let mut a = acc.unwrap_or_default();
                    a.add(c);
                    Some(a)
                }),
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
    let _ = writeln!(m, "`*_nd` recall counts only coverage by offered items that are not `danger`.");
    let _ = writeln!(m, "Danger counts: `danger` = danger items offered for removal (any band but Blocked); `danger_kept` = danger items the engine lists read-only as Blocked; `danger_listed` = both (the number reported as danger before 2026-11-15); `danger_blocking` = danger offered Safe or preselected (RIG.md §7 class (1); the gate criterion).");
    let _ = writeln!(m, "A delete-if-empty item (`RemoveDirIfEmpty`) that still holds something once the plan's other non-danger removals ran is a no-op: outcome `noop_if_nonempty`, no coverage, out of precision; `noop_danger` counts those a plain delete would have made danger (listed below the danger items).\n");
    let _ = writeln!(m, "## Macro (mean over apps per tool)\n");
    let _ = writeln!(
        m,
        "| tool | apps | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_ifempty | noop_danger | Path | RegKey | RegValue | RegValueChanged |"
    );
    let _ = writeln!(m, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for x in macros {
        let pk = |k: &str| pct(x.per_kind_recall.get(k).copied().flatten());
        let _ = writeln!(
            m,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
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
            x.danger_offered,
            x.danger_kept,
            x.danger_listed,
            x.danger_blocking,
            x.danger_preselected,
            x.userdata_preselected,
            x.noop_if_nonempty,
            x.noop_would_be_danger,
            pk("Path"),
            pk("RegKey"),
            pk("RegValue"),
            pk("RegValueChanged")
        );
    }
    let _ = writeln!(m, "\n## Per app\n");
    let _ = writeln!(
        m,
        "| app | tool | offered | truth_n | recall_listed | recall_visible | recall_safe | listed_nd | visible_nd | safe_nd | precision_safe | partial_n | danger | danger_kept | danger_listed | danger_blocking | danger_presel | userdata_presel | noop_danger | hit | danger_outcome | ambient | gone | noop_ifempty | other |"
    );
    let _ = writeln!(m, "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for a in apps {
        for t in &a.tools {
            let o = |k: &str| t.outcomes.get(k).copied().unwrap_or(0);
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
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
                t.danger_offered,
                t.danger_kept,
                t.danger_listed,
                t.danger_blocking,
                t.danger_preselected,
                t.userdata_preselected,
                t.noop_would_be_danger,
                o("hit"),
                o("danger"),
                o("ambient"),
                o("gone"),
                o("noop_if_nonempty"),
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
    let _ = writeln!(m, "\n## Delete-if-empty items that stay (noop_if_nonempty)\n");
    let _ = writeln!(m, "Not danger and no coverage: the target still holds something after the plan's other non-danger removals, so `RemoveDirIfEmpty` leaves it. **would be danger** = a plain delete of the same target would have scored danger; review these by hand.\n");
    let mut any = false;
    for a in apps {
        for t in &a.tools {
            for d in &t.noop {
                any = true;
                let _ = writeln!(
                    m,
                    "- {} / {}: `{}` ({}{}){} - {}",
                    a.id,
                    tool_label(t),
                    md_escape(&d.target),
                    d.band,
                    if d.preselected { ", preselected" } else { "" },
                    if d.would_be_danger { " **would be danger**" } else { "" },
                    md_escape(&d.reasons.join("; "))
                );
            }
        }
    }
    if !any {
        let _ = writeln!(m, "None.");
    }
    if apps.iter().any(|a| a.tools.iter().any(|t| t.pre_same_app_base.is_some())) {
        let _ = writeln!(m, "\n## Earlier install of the same product in snap0\n");
        let _ = writeln!(m, "The run installed and removed the same product before snap0 (run.json `pre`, same ARP key). Offered targets that exist in this snap0 only through that earlier install (absent from the clean run's snap0 / lists-0, last written after it started) are not danger.\n");
        for a in apps {
            for t in a.tools.iter().filter(|t| t.pre_same_app_base.is_some()) {
                let _ = writeln!(
                    m,
                    "- {} / {}: clean reference `{}`; {} offered item(s) not danger for this reason",
                    a.id,
                    tool_label(t),
                    t.pre_same_app_base.as_deref().unwrap_or(""),
                    t.pre_same_app_excused.len()
                );
                for x in &t.pre_same_app_excused {
                    let _ = writeln!(m, "  - `{}`", md_escape(x));
                }
            }
        }
    }
    if apps.iter().any(|a| a.tools.iter().any(|t| t.classes.is_some())) {
        render_classes_md(&mut m, apps);
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

/// The reporting classes (`--classes`): one table, then every class's items. Nothing is left out; the classes
/// only label the danger and user-data items.
fn render_classes_md(m: &mut String, apps: &[AppScore]) {
    let _ = writeln!(m, "\n## Reporting classes\n");
    let _ = writeln!(
        m,
        "(1) **blocking**: danger offered Safe or preselected, and Safe or preselected items over user data (planted files). \
         (2) **unticked**: the same, listed but neither Safe nor preselected (reported, not blocking). \
         (3) reported in their own lists: `preexisting_value_ref` = a value (or list segment) that existed in snap0, is unchanged \
         in snap2 and names a path absent in snap2 (a dangling reference in a value the user or another product created); \
         `old_empty_ext_key` = an `.ext` key (or its OpenWithProgids/OpenWithList) that existed in snap0 with no value below it; \
         `replaced_value` = a value that existed in snap0 and whose data changed by snap2 (the slot now holds the app's record, \
         e.g. `UFH\\SHC|<n>`), offered unticked (Safe or preselected it is blocking). \
         Class (3) items show their band and preselection. `ud_safe` = Safe items over user data, preselected or not.\n"
    );
    let _ = writeln!(m, "| app | tool | danger_blocking | userdata_blocking | danger_unticked | userdata_unticked | preexisting_value_ref | old_empty_ext_key | replaced_value | ud_safe |");
    let _ = writeln!(m, "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    for a in apps {
        for t in &a.tools {
            let Some(c) = &t.classes else { continue };
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                a.id,
                tool_label(t),
                c.danger_blocking,
                c.userdata_blocking,
                c.danger_unticked,
                c.userdata_unticked,
                c.preexisting_value_ref,
                c.old_empty_ext_key,
                c.replaced_value,
                c.userdata_safe
            );
        }
    }
    type ClassList<'a> = (&'a str, &'a dyn Fn(&ItemOutcome) -> bool);
    let lists: [ClassList; 7] = [
        ("(1) blocking danger", &|i| i.class.as_deref() == Some("blocking")),
        ("(1) blocking user data", &|i| i.userdata.as_deref() == Some("blocking")),
        ("(2) unticked danger", &|i| i.class.as_deref() == Some("unticked")),
        ("(2) unticked user data", &|i| i.userdata.as_deref() == Some("unticked")),
        ("(3) preexisting_value_ref", &|i| i.class.as_deref() == Some("preexisting_value_ref")),
        ("(3) old_empty_ext_key", &|i| i.class.as_deref() == Some("old_empty_ext_key")),
        ("(3) replaced_value", &|i| i.class.as_deref() == Some("replaced_value")),
    ];
    for (title, f) in lists {
        let _ = writeln!(m, "\n### {title}\n");
        let mut any = false;
        for a in apps {
            for t in &a.tools {
                for i in t.items.iter().filter(|i| f(i)) {
                    any = true;
                    let _ = writeln!(
                        m,
                        "- {} / {}: `{}` ({}{}{}) {} - {}",
                        a.id,
                        tool_label(t),
                        md_escape(&i.target),
                        i.band,
                        if i.preselected { ", preselected" } else { "" },
                        i.action.as_deref().map(|x| format!(", {x}")).unwrap_or_default(),
                        i.outcome,
                        md_escape(&i.reasons.join("; "))
                    );
                }
            }
        }
        if !any {
            let _ = writeln!(m, "None.");
        }
    }
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
    /// Single-plan mode: the lists file whose system objects count as pre-existing (`--lists0`; for a footprint
    /// score with `--s0` = another run's snap1, that run's lists-1). `--set` finds `lists-*-0.json` itself.
    pub lists0: Option<PathBuf>,
    /// `--classes`: add the reporting classes (RIG.md §7).
    pub classes: bool,
}

struct AppInput {
    id: String,
    dir: String,
    truth: PathBuf,
    s0: PathBuf,
    s2: PathBuf,
    plans: Vec<PathBuf>,
    deny: Option<PathBuf>,
    lists0: Option<PathBuf>,
    /// The run's run.json, when the directory has one (`--set`).
    run: Option<serde_json::Value>,
}

/// run.json `pre` entries that installed and removed the same product as the run itself before snap0: the
/// entry's ARP key is one of the run's `entries_created` keys and its uninstall removed it (`entry_gone`).
/// Returns the earliest such install's start time.
fn pre_same_app_start(run: &serde_json::Value) -> Option<String> {
    let key = |e: &serde_json::Value| e.get("key").and_then(|k| k.as_str()).map(canon::fold);
    let created: Vec<String> = run.get("entries_created")?.as_array()?.iter().filter_map(key).collect();
    run.get("pre")?
        .as_array()?
        .iter()
        .filter(|p| {
            p.get("entry").and_then(key).is_some_and(|k| created.contains(&k))
                && p.pointer("/uninstall/entry_gone").and_then(|x| x.as_bool()) == Some(true)
        })
        .filter_map(|p| p.get("start").and_then(|s| s.as_str()).map(str::to_string))
        .min_by_key(|s| iso_filetime(s).unwrap_or(u64::MAX))
}

/// The clean reference for a run with an earlier install of the same product: another run of the same set on
/// the same machine with no `pre` entries, the nearest in start time.
fn pick_pre_base<'a>(me: &AppInput, all: &'a [AppInput]) -> Option<&'a AppInput> {
    let run = me.run.as_ref()?;
    let comp = run.get("computer").and_then(|c| c.as_str())?;
    let t = run.get("started").and_then(|s| s.as_str()).and_then(iso_filetime)?;
    all.iter()
        .filter(|o| o.dir != me.dir)
        .filter(|o| {
            o.run.as_ref().is_some_and(|r| {
                r.get("computer").and_then(|c| c.as_str()) == Some(comp)
                    && r.get("pre").and_then(|p| p.as_array()).is_none_or(|p| p.is_empty())
                    && r.get("kind").and_then(|k| k.as_str()) != Some("null")
            })
        })
        .min_by_key(|o| {
            let ot = o.run.as_ref().and_then(|r| r.get("started")).and_then(|s| s.as_str()).and_then(iso_filetime).unwrap_or(0);
            ot.abs_diff(t)
        })
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
        lists0: snap::find_phase_file(d, "lists", "0", ".json"),
        run: d.join("run.json").is_file().then(|| jsonio::read::<serde_json::Value>(&d.join("run.json")).ok()).flatten(),
    })
}

fn score_app(a: &AppInput, sid_arg: Option<&str>, classes: bool, all: &[AppInput]) -> Result<AppScore> {
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
    let lists0 = match &a.lists0 {
        Some(p) => Some(ListIdx::load(p)?),
        None => None,
    };
    let mut pre_base = None;
    if let Some(start) = a.run.as_ref().and_then(pre_same_app_start) {
        match (pick_pre_base(a, all), iso_filetime(&start)) {
            (Some(b), Some(ft)) => {
                eprintln!("score: {id}: snap0 holds an earlier install of the same product (started {start}); clean reference {}", b.dir);
                pre_base = Some(PreBase {
                    run: b.dir.clone(),
                    s0: Snap::load(&b.s0, LoadOpts::default())?,
                    lists0: match &b.lists0 {
                        Some(p) => Some(ListIdx::load(p)?),
                        None => None,
                    },
                    since: ft.saturating_sub(120 * 10_000_000),
                });
            }
            _ => eprintln!(
                "score: warning: {id}: snap0 holds an earlier install of the same product, but no clean run of the same machine is in the set: its leftovers in snap0 score as danger"
            ),
        }
    }
    let cx = Ctx {
        truth: &idx,
        s0: &s0,
        s2: &s2,
        deny: &deny,
        sid: sid.as_deref(),
        links: &links,
        lists0: lists0.as_ref(),
        classes,
        pre_base: pre_base.as_ref(),
    };
    let mut tools = Vec::new();
    for p in &a.plans {
        let plan: Plan = jsonio::read(p)?;
        if !plan.app.is_empty() && !plan.app.eq_ignore_ascii_case(&id) {
            eprintln!("score: warning: {} is for app {:?}, scoring it against {id:?}", p.display(), plan.app);
        }
        let s = score_plan(&cx, &id, &plan, &p.display().to_string());
        eprintln!(
            "score: {id} / {}: offered {} truth {} recall_visible_nd {} danger_blocking {} danger_preselected {} userdata_preselected {} (danger offered {}, kept {})",
            tool_label(&s),
            s.offered_n,
            s.truth_n,
            pct(s.recall_visible_nd),
            s.danger_blocking,
            s.danger_preselected,
            s.userdata_preselected,
            s.danger_offered,
            s.danger_kept
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
            lists0: a.lists0.clone(),
            run: None,
        });
    }
    if inputs.is_empty() {
        bail!("score: give --set APPDIR... or --plan/--truth/--s0/--s2");
    }
    let mut apps = Vec::new();
    for i in &inputs {
        apps.push(score_app(i, a.sid.as_deref(), a.classes, &inputs)?);
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
        PlanItem { target: t, band: band.into(), preselected: pre, scanner: Some("S".into()), category: None, action: None }
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
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links, lists0: None, classes: false, pre_base: None };
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
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links, lists0: None, classes: false, pre_base: None };
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
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links, lists0: None, classes: false, pre_base: None };
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
        let cx = Ctx { truth: &idx, s0, s2, deny: &deny, sid: Some(SID), links: &links, lists0: None, classes: false, pre_base: None };
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

    fn act(mut i: PlanItem, a: &str) -> PlanItem {
        i.action = Some(a.into());
        i
    }

    /// firefox-tb shape: `HKU\..\Software\Mozilla` existed in snap0 (Thunderbird's key inside it); the app's
    /// `Mozilla\Firefox` is new. The plan deletes `Firefox` and offers the vendor key delete-if-empty.
    fn vendor_fixture() -> (Snap, Snap, Vec<TruthItem>) {
        let u = format!("HKU\\{SID}\\Software");
        let roots = [u.as_str(), "C:\\Users"];
        let s0 = snap_with_roots(&roots, |t| {
            write_k(t, &u, 1, Some(0), Some(1));
            write_k(t, &format!("{u}\\Mozilla"), 1, Some(0), Some(1));
            write_k(t, &format!("{u}\\Mozilla\\Thunderbird"), 1, Some(1), Some(0));
            write_v(t, &format!("{u}\\Mozilla\\Thunderbird"), "v", 1, 2, 1, "x");
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_k(t, &u, 1, Some(0), Some(1));
            write_k(t, &format!("{u}\\Mozilla"), 2, Some(0), Some(2));
            write_k(t, &format!("{u}\\Mozilla\\Thunderbird"), 1, Some(1), Some(0));
            write_v(t, &format!("{u}\\Mozilla\\Thunderbird"), "v", 1, 2, 1, "x");
            write_k(t, &format!("{u}\\Mozilla\\Firefox"), 2, Some(1), Some(0));
            write_v(t, &format!("{u}\\Mozilla\\Firefox"), "Launcher", 1, 2, 2, "y");
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\Vendor", 0x10, 2, 0);
            write_d(t, "C:\\Users\\t\\Vendor\\App", 0x10, 2, 0);
            write_f(t, "C:\\Users\\t\\Vendor\\App\\a.dat", 1, 0x20, 2, 0);
        });
        let truth = vec![
            ti(Target::RegKey { path: format!("{u}\\Mozilla\\Firefox") }, "leftover"),
            ti(Target::Path { path: "C:\\Users\\t\\Vendor".into() }, "leftover"),
        ];
        (s0, s2, truth)
    }

    #[test]
    fn delete_if_empty_on_a_nonempty_preexisting_key_is_reported_not_danger() {
        let (s0, s2, truth) = vendor_fixture();
        let u = format!("HKU\\{SID}\\Software");
        let s = score_one(
            &s0,
            &s2,
            truth,
            vec![
                act(item(Target::RegKey { path: format!("{u}\\Mozilla\\Firefox") }, "Safe", true), "DeleteKey"),
                act(item(Target::RegKey { path: format!("{u}\\Mozilla") }, "Weak", false), "RemoveDirIfEmpty"),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["hit", "noop_if_nonempty"]);
        assert_eq!(s.danger_listed, 0);
        assert_eq!((s.noop_if_nonempty, s.noop_would_be_danger), (1, 1));
        let n = &s.noop[0];
        assert!(n.would_be_danger && n.covers == 0 && n.partial == 0);
        assert!(n.reasons[0].contains("Thunderbird") && n.reasons[0].contains("existed in snap0"), "{:?}", n.reasons);
        assert!(n.reasons.iter().any(|r| r.starts_with("as a plain delete: existed in snap0")), "{:?}", n.reasons);
        assert_eq!(s.outcomes["noop_if_nonempty"], 1);
        // The same item without an action (a plain delete, as the old tools' plans) stays danger.
        let (s0, s2, truth) = vendor_fixture();
        let s = score_one(&s0, &s2, truth, vec![item(Target::RegKey { path: format!("{u}\\Mozilla") }, "Weak", false)]);
        assert_eq!(s.items[0].outcome, "danger");
        assert_eq!(s.noop_if_nonempty, 0);
    }

    #[test]
    fn delete_if_empty_that_empties_scores_like_a_delete_and_inner_first() {
        let (s0, s2, truth) = vendor_fixture();
        // Vendor\App\a.dat is removed by a quarantine of App; App (inner, if-empty) empties first, then Vendor.
        let s = score_one(
            &s0,
            &s2,
            truth.clone(),
            vec![
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor".into() }, "Safe", true), "RemoveDirIfEmpty"),
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor\\App\\a.dat".into() }, "Safe", true), "Quarantine"),
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor\\App".into() }, "Safe", true), "RemoveDirIfEmpty"),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["hit", "hit", "hit"]);
        assert_eq!(s.recall_safe_nd, Some(0.5));
        // Without the file's removal both containers stay: no coverage, no precision effect.
        let s = score_one(
            &s0,
            &s2,
            truth,
            vec![
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor".into() }, "Safe", true), "RemoveDirIfEmpty"),
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor\\App".into() }, "Safe", true), "RemoveDirIfEmpty"),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["noop_if_nonempty", "noop_if_nonempty"]);
        assert_eq!((s.noop_would_be_danger, s.recall_listed), (0, Some(0.0)));
        assert_eq!(s.precision_safe, None);
    }

    #[test]
    fn delete_if_empty_of_a_preexisting_container_that_empties_is_danger() {
        // A pre-existing (empty in snap0) container whose only content is new and removed by the plan: the
        // if-empty item really deletes a pre-existing dir, so it stays danger.
        let roots = ["C:\\Users"];
        let s0 = snap_with_roots(&roots, |t| {
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\Vendor", 0x10, 1, 0);
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\Vendor", 0x10, 2, 0);
            write_d(t, "C:\\Users\\t\\Vendor\\App", 0x10, 2, 0);
        });
        let truth = vec![ti(Target::Path { path: "C:\\Users\\t\\Vendor\\App".into() }, "leftover")];
        let s = score_one(
            &s0,
            &s2,
            truth,
            vec![
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor\\App".into() }, "Safe", true), "Quarantine"),
                act(item(Target::Path { path: "C:\\Users\\t\\Vendor".into() }, "Weak", false), "RemoveDirIfEmpty"),
            ],
        );
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["hit", "danger"]);
        assert_eq!(s.noop_if_nonempty, 0);
    }

    #[test]
    fn plan_action_round_trips() {
        let p: Plan = serde_json::from_value(json!({"items": [
            {"target": {"type": "Path", "path": "C:\\x"}, "band": "Weak", "action": "RemoveDirIfEmpty"},
            {"target": {"type": "Path", "path": "C:\\y"}, "band": "Safe"}
        ]}))
        .unwrap();
        assert!(is_if_empty(p.items[0].action.as_deref()));
        assert!(!is_if_empty(p.items[1].action.as_deref()));
        assert!(removes(None) && removes(Some("Quarantine")) && !removes(Some("EditSegment")) && !removes(Some("ReportOnly")));
    }

    fn score_cx(s0: &Snap, s2: &Snap, truth: Vec<TruthItem>, offered: Vec<PlanItem>, lists0: Option<&ListIdx>) -> ToolScore {
        let idx = TruthIdx::new(truth, Some(SID));
        let deny = Deny::default();
        let links = LinkMap::new(s0.reg_links().into_iter().chain(s2.reg_links()));
        let cx = Ctx { truth: &idx, s0, s2, deny: &deny, sid: Some(SID), links: &links, lists0, classes: true, pre_base: None };
        score_plan(&cx, "app", &Plan { tool: "t".into(), items: offered, ..Default::default() }, "p.json")
    }

    #[test]
    fn system_objects_in_lists0_are_danger() {
        let roots = ["HKLM\\SOFTWARE"];
        let s0 = snap_with_roots(&roots, |t| write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(0)));
        let s2 = snap_with_roots(&roots, |t| write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(0)));
        let l0 = ListIdx::from_value(&json!({
            "appx": [{"full_name": "Microsoft.VisualStudioCode_1.0.0.0_neutral__8wekyb3d8bbwe"}],
            "tasks": [{"path": "\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB"}],
            "services": [{"name": "MozillaMaintenance"}],
            "firewall": [{"id": "{ABC}"}]
        }));
        let offered = vec![
            item(Target::AppxPackage { full_name: "Microsoft.VisualStudioCode_1.0.0.0_neutral__8wekyb3d8bbwe".into() }, "Likely", false),
            item(Target::AppxPackage { full_name: "Other_1.0.0.0_neutral__x".into() }, "Likely", false),
            item(Target::Task { path: "Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB".into() }, "Safe", true),
            item(Target::Service { name: "mozillamaintenance".into() }, "Weak", false),
            item(Target::FirewallRule { id: "{ABC}".into() }, "Weak", false),
        ];
        let s = score_cx(&s0, &s2, vec![], offered.clone(), Some(&l0));
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["danger", "other", "danger", "danger", "danger"]);
        assert!(s.items[0].reasons[0].starts_with("existed in lists-0: A:Microsoft.VisualStudioCode"), "{:?}", s.items[0].reasons);
        assert_eq!((s.danger_listed, s.danger_preselected), (4, 1));
        // Without lists-0 nothing changes (older runs, M0).
        let s = score_cx(&s0, &s2, vec![], offered, None);
        assert_eq!(s.danger_listed, 0);
    }

    #[test]
    fn reporting_classes() {
        let u = format!("HKU\\{SID}");
        let roots = [u.as_str(), "HKLM\\SOFTWARE", "C:\\Program Files", "C:\\Users"];
        let body = |t: &mut String, after: bool| {
            write_k(t, &u, 1, Some(0), Some(1));
            write_k(t, &format!("{u}\\Software"), 1, Some(0), Some(1));
            write_k(t, &format!("{u}\\Software\\TortoiseGit"), 1, Some(2), Some(0));
            // a dangling reference another product wrote before the install
            write_v(t, &format!("{u}\\Software\\TortoiseGit"), "MSysGit", 1, 10, 7, "C:\\Program Files\\Git\\bin");
            // a reference to something that still exists (a portable copy): not dangling
            write_v(t, &format!("{u}\\Software\\TortoiseGit"), "Portable", 1, 10, 8, "\"C:\\Users\\t\\Tools\\npp\\notepad++.exe\" \"%1\"");
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes", 1, Some(0), Some(3));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\.sh", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\.sh\\OpenWithProgids", 1, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\.e3", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Classes\\.e3\\OpenWithProgids", 1, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Classes\\.e3\\OpenWithProgids", "MyEditor.e3", 0, 0, 9, "");
            write_k(t, "HKLM\\SOFTWARE\\Classes\\Old", 1, Some(0), Some(0));
            write_d(t, "C:\\Program Files", 0x10, 1, 0);
            write_d(t, "C:\\Users", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\Tools", 0x10, 1, 0);
            write_d(t, "C:\\Users\\t\\Tools\\npp", 0x10, 1, 0);
            write_f(t, "C:\\Users\\t\\Tools\\npp\\notepad++.exe", 9, 0x20, 1, 0);
            if after {
                write_d(t, "C:\\Program Files\\App", 0x10, 2, 0);
                write_f(t, "C:\\Program Files\\App\\a.exe", 1, 0x20, 2, 0);
                write_f(t, "C:\\Program Files\\App\\notes.txt", 1, 0x20, 2, 0);
            }
        };
        let s0 = snap_with_roots(&roots, |t| body(t, false));
        let s2 = snap_with_roots(&roots, |t| body(t, true));
        let truth = vec![
            ti(Target::Path { path: "C:\\Program Files\\App\\a.exe".into() }, "leftover"),
            ti(Target::Path { path: "C:\\Program Files\\App\\notes.txt".into() }, "user_data"),
        ];
        let v = |k: &str, n: &str| Target::RegValue { path: k.into(), name: n.into() };
        let k = |p: &str| Target::RegKey { path: p.into() };
        let tg = format!("{u}\\Software\\TortoiseGit");
        let offered = vec![
            item(v(&tg, "MSysGit"), "Safe", true),
            item(v(&tg, "Portable"), "Safe", true),
            item(k("HKLM\\SOFTWARE\\Classes\\Old"), "Weak", false),
            item(k("HKLM\\SOFTWARE\\Classes\\.sh"), "Safe", true),
            item(k("HKLM\\SOFTWARE\\Classes\\.e3"), "Safe", true),
            item(Target::Path { path: "C:\\Program Files\\App".into() }, "Safe", true),
            item(Target::Path { path: "C:\\Program Files\\App\\notes.txt".into() }, "Likely", false),
        ];
        let s = score_cx(&s0, &s2, truth, offered, None);
        let cl: Vec<Option<&str>> = s.items.iter().map(|i| i.class.as_deref()).collect();
        assert_eq!(
            cl,
            vec![
                Some("preexisting_value_ref"),
                Some("blocking"),
                Some("unticked"),
                Some("old_empty_ext_key"),
                Some("blocking"),
                None,
                None
            ]
        );
        let ud: Vec<Option<&str>> = s.items.iter().map(|i| i.userdata.as_deref()).collect();
        assert_eq!(ud[5..], [Some("blocking"), Some("unticked")]);
        let c = s.classes.clone().unwrap();
        assert_eq!((c.danger_blocking, c.danger_unticked, c.preexisting_value_ref, c.old_empty_ext_key), (2, 1, 1, 1));
        assert_eq!((c.userdata_blocking, c.userdata_unticked, c.userdata_safe), (1, 1, 1));
        // Every danger item is in exactly one danger class.
        assert_eq!(c.danger_blocking + c.danger_unticked + c.preexisting_value_ref + c.old_empty_ext_key + c.replaced_value, s.danger_listed);
        assert_eq!(s.danger_blocking, c.danger_blocking);
        let md = render_md(&[AppScore { id: "a".into(), tools: vec![s], ..Default::default() }], &[]);
        assert!(md.contains("## Reporting classes") && md.contains("### (3) old_empty_ext_key"));
        assert_eq!(data_path("\"C:\\A B\\x.exe\" --hide"), Some("C:\\A B\\x.exe".into()));
        assert_eq!(data_path("C:\\Program Files\\Git\\bin\\"), Some("C:\\Program Files\\Git\\bin".into()));
        assert_eq!(data_path("powershell -File C:\\x.ps1"), None);
    }

    #[test]
    fn iso_times_convert_to_filetime() {
        // 1970-01-01T00:00:00Z = 116444736000000000
        assert_eq!(iso_filetime("1970-01-01T00:00:00Z"), Some(116_444_736_000_000_000));
        assert_eq!(iso_filetime("1970-01-01T03:00:00+03:00"), Some(116_444_736_000_000_000));
        assert_eq!(iso_filetime("1970-01-01T00:00:01.5-00:00"), Some(116_444_736_015_000_000));
        let a = iso_filetime("2026-11-15T05:17:05.9420226+03:00").unwrap();
        let b = iso_filetime("2026-11-15T02:17:05.9420226Z").unwrap();
        assert_eq!(a, b);
        assert_eq!(iso_filetime("nonsense"), None);
    }

    #[test]
    fn blocked_danger_is_kept_not_offered_and_replaced_values_get_their_class() {
        let roots = ["HKU\\S-1-5-21-7-7-7-1001"];
        let shc = "HKU\\S-1-5-21-7-7-7-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC";
        let s0 = snap_with_roots(&roots, |t| {
            write_k(t, shc, 1, Some(2), Some(0));
            write_v(t, shc, "15", 7, 10, 1, "C:\\Old.lnk");
            write_v(t, shc, "3", 7, 10, 3, "C:\\Kept.lnk");
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_k(t, shc, 2, Some(2), Some(0));
            write_v(t, shc, "15", 7, 10, 2, "C:\\App.lnk");
            write_v(t, shc, "3", 7, 10, 3, "C:\\Kept.lnk");
        });
        let v = |n: &str| Target::RegValue { path: shc.into(), name: n.into() };
        let offered = vec![
            item(v("15"), "Likely", false), // replaced, unticked
            item(v("3"), "Blocked", false), // kept, read-only
            item(v("15"), "Safe", false),   // replaced but Safe: blocking
        ];
        let s = score_cx(&s0, &s2, vec![], offered, None);
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["danger", "danger", "danger"]);
        let cl: Vec<&str> = s.items.iter().map(|i| i.class.as_deref().unwrap_or("")).collect();
        assert_eq!(cl, vec!["replaced_value", "unticked", "blocking"]);
        assert_eq!((s.danger_listed, s.danger_offered, s.danger_kept, s.danger_blocking), (3, 2, 1, 1));
        assert!(s.items[0].reasons.iter().any(|r| r.contains("before `C:\\Old.lnk`, after `C:\\App.lnk`")), "{:?}", s.items[0].reasons);
        let c = s.classes.as_ref().unwrap();
        assert_eq!(c.replaced_value, 1);
        let md = render_md(&[AppScore { id: "a".into(), tools: vec![s], ..Default::default() }], &[]);
        assert!(md.contains("### (3) replaced_value") && md.contains("| danger | danger_kept | danger_listed | danger_blocking |"));
    }

    #[test]
    fn earlier_install_of_the_same_product_is_not_danger() {
        let roots = ["HKLM\\SOFTWARE", "C:\\ProgramData"];
        // FILETIMEs: the earlier install started at 1000, the reference snapshot's state is older.
        let s0 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Vendor", 1, Some(0), Some(0)); // old, also in the reference: foreign
            write_k(t, "HKLM\\SOFTWARE\\Vendor\\App", 1500, Some(0), Some(0)); // the first install's key
            write_k(t, "HKLM\\SOFTWARE\\Other", 500, Some(0), Some(0)); // absent from the reference but written before
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
            write_d(t, "C:\\ProgramData\\App", 0x10, 1600, 0);
        });
        let s2 = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Vendor", 1, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Vendor\\App", 1500, Some(0), Some(0));
            write_k(t, "HKLM\\SOFTWARE\\Other", 500, Some(0), Some(0));
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
            write_d(t, "C:\\ProgramData\\App", 0x10, 1600, 0);
        });
        let base = snap_with_roots(&roots, |t| {
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Vendor", 1, Some(0), Some(0));
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
        });
        let pb = PreBase { run: "runs/clean".into(), s0: base, lists0: Some(ListIdx::default()), since: 1000 };
        let l0 = ListIdx::from_value(&json!({"tasks": [{"path": "\\Vendor\\App Task"}]}));
        let k = |p: &str| Target::RegKey { path: p.into() };
        let offered = vec![
            item(k("HKLM\\SOFTWARE\\Vendor\\App"), "Safe", true),
            item(Target::Path { path: "C:\\ProgramData\\App".into() }, "Safe", true),
            item(Target::Task { path: "Vendor\\App Task".into() }, "Safe", true),
            item(k("HKLM\\SOFTWARE\\Vendor"), "Likely", false),
            item(k("HKLM\\SOFTWARE\\Other"), "Likely", false),
        ];
        let idx = TruthIdx::new(vec![], Some(SID));
        let deny = Deny::default();
        let links = LinkMap::default();
        let cx = Ctx { truth: &idx, s0: &s0, s2: &s2, deny: &deny, sid: Some(SID), links: &links, lists0: Some(&l0), classes: false, pre_base: Some(&pb) };
        let s = score_plan(&cx, "app", &Plan { tool: "t".into(), items: offered, ..Default::default() }, "p.json");
        let oc: Vec<&str> = s.items.iter().map(|i| i.outcome.as_str()).collect();
        assert_eq!(oc, vec!["other", "other", "other", "danger", "danger"]);
        assert_eq!((s.danger_blocking, s.danger_preselected), (0, 0));
        assert_eq!(s.pre_same_app_excused.len(), 3);
        assert_eq!(s.pre_same_app_base.as_deref(), Some("runs/clean"));
        // without the reference the same plan is danger throughout
        let cx2 = Ctx { pre_base: None, ..cx };
        let s = score_plan(&cx2, "app", &Plan { tool: "t".into(), items: vec![item(k("HKLM\\SOFTWARE\\Vendor\\App"), "Safe", true)], ..Default::default() }, "p.json");
        assert_eq!((s.danger_blocking, s.danger_preselected), (1, 1));
    }

    #[test]
    fn pre_same_app_is_the_runs_own_removed_entry() {
        let run = json!({
            "entries_created": [{"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox"}],
            "pre": [
                {"start": "2026-11-15T05:17:05+03:00", "entry": {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox"}, "uninstall": {"entry_gone": true}},
                {"start": "2026-11-15T05:10:00+03:00", "entry": {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Thunderbird"}}
            ]
        });
        assert_eq!(pre_same_app_start(&run).as_deref(), Some("2026-11-15T05:17:05+03:00"));
        // a still-installed sibling (no uninstall) is not the same product's earlier install
        let sib = json!({
            "entries_created": [{"key": "X\\Mozilla Firefox"}],
            "pre": [{"start": "2026-11-15T05:17:05+03:00", "entry": {"key": "X\\Firefox ESR"}}]
        });
        assert_eq!(pre_same_app_start(&sib), None);
    }
}
