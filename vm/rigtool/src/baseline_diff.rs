//! `rigtool baseline-diff` (RIG.md §8a; docs/BASELINE_LOCAL_DESIGN.md §8.1, package BL-RIG-DIFF): how much of a
//! shipped clean-Windows baseline (the *truth*) a local baseline, alone and merged with shipped neighbours, covers,
//! per registry area of `kb/baselines/view.json`.
//!
//! The diff works on **names**, never on hashes: every `K` record of every file is unescaped, folded and normalised
//! as the engine normalises a baseline key (a mirror of `purge_index::baseline`: the engine's Windows fold, roots,
//! control sets, user SIDs to `<sid>`, `HKU\<sid>\Software\Classes` to `HKU\<sid>_Classes`, `HKU\S-1-5-18` to
//! `HKU\.DEFAULT`, `HKLM\SOFTWARE\WOW6432Node\Classes` to `…\Classes\WOW6432Node`) and kept as text. Only keys inside
//! the capture scope (`Baseline::key_in_scope`) are compared; `V`, `D` and `F` records are counted, not compared. A
//! truth key counts as covered by a set when the set has it or, for a 32-bit-view spelling, its 64-bit twin (the
//! rule of `Baseline::has_key`).
//!
//! Per area and in total the report gives: truth keys; covered by the local set and by the union of all sets;
//! false absent (in truth, in no set) for both; extra (in a set, not in truth); per set the covered keys, the keys
//! only that set covers and its share of the merged coverage; the false-absent keys of a shared-container shape
//! ([`Shape`]) by shape; the first [`FIRST_N`] false-absent keys of each area; and the mechanical S2 / S3 checks of
//! design §8.3 for that one pair. Every false-absent key of a shared-container shape is listed by name in
//! `shared_shape_false_absent`, with the sets that have it and the source that should have had it (a heuristic by
//! root, for the reviewer).

use crate::err::{Context, Result, bail};
use crate::escape::unescape;
use crate::jsonio;
use crate::snap::open_text;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The report's schema.
pub const SCHEMA: &str = "purge.baseline-diff/1";
/// The area file's schema (`kb/baselines/view.json`).
pub const VIEW_SCHEMA: &str = "purge.baseline-view/1";
/// False-absent keys listed per area (each of local-only and merged).
pub const FIRST_N: usize = 200;
/// S2 / S3 (design §8.3): other false-absent keys at most this share of the area's truth keys.
pub const OTHER_FALSE_ABSENT_MAX: f64 = 0.005;
/// W1 (design §8.4): merged coverage over the scope.
pub const W1_SCOPE: f64 = 0.99;
/// W1: merged coverage in an area marked `merged`.
pub const W1_AREA: f64 = 0.998;
/// The id of the implicit area that takes every key no area of the file matches.
pub const UNMATCHED: &str = "(unmatched)";

const SHIPPED_TAG: &str = "#purge-baseline";
const LOCAL_TAG: &str = "#purge-baseline-local";
const REQUIRED_SOURCES: [&str; 4] = ["S1", "S2", "S3", "S4"];

pub struct DiffArgs {
    pub truth: PathBuf,
    pub local: PathBuf,
    pub neighbours: Vec<PathBuf>,
    pub areas: PathBuf,
    pub out: PathBuf,
}

// ---------------------------------------------------------------------------------------------------------------
// Normalisation: a mirror of purge_index::baseline (fold_char of purge_model::object, normalise_key, key_forms,
// key_in_scope). A change there must be made here too.
// ---------------------------------------------------------------------------------------------------------------

const WINDOWS_KEEPS_APART: &[(u32, u32)] = &[
    (0x01C5, 0x01C5),
    (0x01C8, 0x01C8),
    (0x01CB, 0x01CB),
    (0x01F2, 0x01F2),
    (0x037F, 0x037F),
    (0x0524, 0x052F),
    (0x10C7, 0x10CD),
    (0x13A0, 0x13F5),
    (0x1C90, 0x1CBF),
    (0x2C2F, 0x2C2F),
    (0x2C70, 0x2C70),
    (0x2C7E, 0x2C7F),
    (0x2CEB, 0x2CF2),
    (0xA660, 0xA660),
    (0xA698, 0xA69A),
    (0xA78D, 0xA7F5),
];

/// The engine's fold (`purge_model::object::fold`): ASCII lower case; another letter only when its lower-case form
/// is the same letter and Windows folds it.
pub fn fold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let code = u32::from(c);
        let apart = code > 0xFFFF || WINDOWS_KEEPS_APART.iter().any(|(a, b)| (*a..=*b).contains(&code));
        if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else if !apart && c.to_lowercase().flat_map(char::to_uppercase).eq(c.to_uppercase()) {
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

const HKLM_CLASSES: &str = "hklm\\software\\classes";
const HKU_CLASSES: &str = "hku\\<sid>_classes";
const WOW: &str = "\\wow6432node";

fn is_user_sid(segment: &str) -> bool {
    let rest = segment.strip_prefix("s-1-5-21-").or_else(|| segment.strip_prefix("s-1-12-1-"));
    rest.is_some_and(|r| {
        r.starts_with(|c: char| c.is_ascii_digit()) && r.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    })
}

fn replace_head(key: &mut String, head: &str, with: &str) {
    if key.starts_with(head) && matches!(key.as_bytes().get(head.len()), None | Some(b'\\')) {
        key.replace_range(..head.len(), with);
    }
}

/// The normalised form of an already folded key.
fn normalise_folded(folded: &str) -> String {
    let mut out = String::with_capacity(folded.len());
    for (i, segment) in folded.split('\\').filter(|s| !s.is_empty()).enumerate() {
        if i > 0 {
            out.push('\\');
        }
        match segment {
            "hkey_local_machine" if i == 0 => out.push_str("hklm"),
            "hkey_users" if i == 0 => out.push_str("hku"),
            "hkcu" | "hkey_current_user" if i == 0 => out.push_str("hku\\<sid>"),
            _ => match segment.strip_suffix("_classes") {
                Some(sid) if is_user_sid(sid) => out.push_str("<sid>_classes"),
                _ if is_user_sid(segment) => out.push_str("<sid>"),
                _ => out.push_str(segment),
            },
        }
    }
    if out.starts_with("hklm\\system\\controlset") {
        let head = "hklm\\system\\controlset".len();
        let digits = out.as_bytes()[head..].iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 3 && matches!(out.as_bytes().get(head + 3), None | Some(b'\\')) {
            out.replace_range(.."hklm\\system\\controlset000".len(), "hklm\\system\\currentcontrolset");
        }
    } else if out.starts_with("hku\\") {
        replace_head(&mut out, "hku\\s-1-5-18", "hku\\.default");
        replace_head(&mut out, "hku\\<sid>\\software\\wow6432node\\classes", "hku\\<sid>_classes\\wow6432node");
        replace_head(&mut out, "hku\\<sid>\\software\\classes", "hku\\<sid>_classes");
    } else {
        replace_head(&mut out, "hklm\\software\\wow6432node\\classes", "hklm\\software\\classes\\wow6432node");
    }
    out
}

/// The normalised form of a key as written in a baseline file (`HKCR` reads as the machine classes; the files never
/// use it).
pub fn normalise(key: &str) -> String {
    let folded = fold(key);
    let trimmed = folded.trim_start_matches('\\');
    match trimmed.split_once('\\') {
        Some(("hkcr" | "hkey_classes_root", rest)) => normalise_folded(&format!("{HKLM_CLASSES}\\{rest}")),
        _ => normalise_folded(trimmed),
    }
}

/// The 64-bit twin of a normalised 32-bit-view spelling (`Baseline::has_key` also matches it).
pub fn twin(norm: &str) -> Option<String> {
    [HKLM_CLASSES, HKU_CLASSES, "hklm\\software"].iter().find_map(|head| {
        let below = norm.strip_prefix(head)?.strip_prefix(WOW)?;
        (below.is_empty() || below.starts_with('\\')).then(|| format!("{head}{below}"))
    })
}

fn under(path: &str, root: &str) -> bool {
    path.strip_prefix(root).is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}

/// `Baseline::key_in_scope` on a normalised key: what the rig captures (RIG.md §2).
pub fn in_scope(norm: &str) -> bool {
    if under(norm, "hklm\\system\\currentcontrolset") {
        !under(norm, "hklm\\system\\currentcontrolset\\enum")
            && !under(norm, "hklm\\system\\currentcontrolset\\control\\deviceclasses")
    } else {
        under(norm, "hklm\\software") || norm.starts_with("hku\\")
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Shared-container shapes (design §8.1)
// ---------------------------------------------------------------------------------------------------------------

/// The shape of a key that many programs share, so a false "absent" there is the costly kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shape {
    /// `Classes\.ext`.
    Ext,
    /// `Classes\.ext\OpenWithProgids`.
    ExtOpenWithProgids,
    /// `Classes\…\shell`.
    Shell,
    /// `Classes\…\shellex` and its direct children (`shellex\ContextMenuHandlers`, …).
    Shellex,
    /// A top-level key of Classes that is not a `.ext` nor one of the structural keys ([`STRUCTURAL`]).
    ProgId,
    /// `SOFTWARE\<name>` (also under `WOW6432Node` and in a user hive).
    VendorDepth1,
    /// `SOFTWARE\<name>\<name>`.
    VendorDepth2,
}

impl Shape {
    pub fn name(self) -> &'static str {
        match self {
            Shape::Ext => "ext",
            Shape::ExtOpenWithProgids => "ext_openwithprogids",
            Shape::Shell => "shell",
            Shape::Shellex => "shellex",
            Shape::ProgId => "progid",
            Shape::VendorDepth1 => "vendor_depth1",
            Shape::VendorDepth2 => "vendor_depth2",
        }
    }
    pub const ALL: [Shape; 7] = [
        Shape::Ext,
        Shape::ExtOpenWithProgids,
        Shape::Shell,
        Shape::Shellex,
        Shape::ProgId,
        Shape::VendorDepth1,
        Shape::VendorDepth2,
    ];
}

/// Top-level keys of Classes that hold other kinds of registration, not a ProgID.
pub const STRUCTURAL: [&str; 9] = [
    "clsid",
    "interface",
    "typelib",
    "appid",
    "wow6432node",
    "mime",
    "componentcategories",
    "record",
    "local settings",
];

/// The segments of `norm` below the first of `roots` it lies under.
fn below<'a>(norm: &'a str, roots: &[&str]) -> Option<Vec<&'a str>> {
    roots.iter().find_map(|r| {
        let rest = norm.strip_prefix(r)?;
        if rest.is_empty() { Some(Vec::new()) } else { rest.strip_prefix('\\').map(|x| x.split('\\').collect()) }
    })
}

/// The shared-container shape of a normalised key, if it has one.
pub fn shape(norm: &str) -> Option<Shape> {
    // The 32-bit roots first, so `Classes\WOW6432Node\X` is X of the 32-bit classes.
    const CLASSES: [&str; 4] =
        ["hklm\\software\\classes\\wow6432node", "hku\\<sid>_classes\\wow6432node", HKLM_CLASSES, HKU_CLASSES];
    if let Some(r) = below(norm, &CLASSES) {
        return match r.as_slice() {
            [] => None,
            [one] if one.starts_with('.') => Some(Shape::Ext),
            [one] if STRUCTURAL.contains(one) => None,
            [_] => Some(Shape::ProgId),
            [ext, "openwithprogids"] if ext.starts_with('.') => Some(Shape::ExtOpenWithProgids),
            [.., "shell"] => Some(Shape::Shell),
            // `shellex` (not the first segment) itself or a direct child of it.
            _ if r.iter().enumerate().skip(1).any(|(i, s)| *s == "shellex" && i + 2 >= r.len()) => Some(Shape::Shellex),
            _ => None,
        };
    }
    const SOFTWARE: [&str; 6] = [
        "hklm\\software\\wow6432node",
        "hku\\<sid>\\software\\wow6432node",
        "hku\\.default\\software\\wow6432node",
        "hklm\\software",
        "hku\\<sid>\\software",
        "hku\\.default\\software",
    ];
    match below(norm, &SOFTWARE)?.as_slice() {
        [one] if *one != "wow6432node" && *one != "classes" => Some(Shape::VendorDepth1),
        [one, _] if *one != "wow6432node" && *one != "classes" => Some(Shape::VendorDepth2),
        _ => None,
    }
}

/// Which source of the local baseline should have had a false-absent key (a heuristic by root, for the reviewer).
pub fn expected_source(norm: &str) -> &'static str {
    if under(norm, HKU_CLASSES) {
        "none: user classes have no template (first logon, apps); a neighbour"
    } else if under(norm, "hku\\<sid>") {
        "S2 (default profile hive), else first logon: a neighbour"
    } else if under(norm, "hku\\.default") {
        "S3 (HKU\\.DEFAULT)"
    } else if norm.starts_with("hku\\") {
        "none: service profile hive; a neighbour"
    } else if below(norm, &[HKLM_CLASSES]).is_some_and(|r| r.first().is_some_and(|s| s.starts_with("appx"))) {
        "S4 (inbox package repository)"
    } else if under(norm, "hklm\\system\\currentcontrolset\\services") {
        "S1, else S5 (INF, not built)"
    } else {
        "S1 (component manifests), else OOBE / first start: a neighbour"
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Areas (kb/baselines/view.json)
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewFile {
    schema: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<Value>,
    #[serde(default)]
    #[allow(dead_code)]
    neighbours: Option<Value>,
    areas: Vec<AreaDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AreaDef {
    id: String,
    #[serde(default)]
    title: String,
    prefixes: Vec<String>,
    #[serde(default)]
    shape: Option<String>,
    #[serde(default)]
    merged: bool,
    #[serde(default)]
    local: bool,
}

/// What an area asks of the segments below its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaShape {
    /// Anything at or below the prefix.
    Any,
    /// The first segment below the prefix starts with `.`.
    Ext,
    /// A segment after the first below the prefix is `shell` or `shellex`.
    Shell,
}

#[derive(Debug, Clone)]
pub struct Area {
    pub id: String,
    pub title: String,
    pub prefixes: Vec<String>,
    pub shape: AreaShape,
    pub merged: bool,
    pub local: bool,
}

impl Area {
    fn matches(&self, norm: &str) -> bool {
        self.prefixes.iter().any(|p| {
            let Some(r) = below(norm, &[p.as_str()]) else { return false };
            match self.shape {
                AreaShape::Any => true,
                AreaShape::Ext => r.first().is_some_and(|s| s.starts_with('.')),
                AreaShape::Shell => r.iter().skip(1).any(|s| *s == "shell" || *s == "shellex"),
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct Areas {
    pub list: Vec<Area>,
}

impl Areas {
    pub fn parse(text: &str) -> Result<Areas> {
        let f: ViewFile = serde_json::from_str(text).context("view.json")?;
        if f.schema != VIEW_SCHEMA {
            bail!("view.json: schema {:?}, expected {VIEW_SCHEMA:?}", f.schema);
        }
        let mut seen = HashSet::new();
        let mut list = Vec::new();
        for a in f.areas {
            if a.id.is_empty() || a.id == UNMATCHED || !seen.insert(a.id.clone()) {
                bail!("view.json: area id {:?} is empty, reserved or not unique", a.id);
            }
            if a.prefixes.is_empty() {
                bail!("view.json: area {} has no prefix", a.id);
            }
            for p in &a.prefixes {
                if p.is_empty() || normalise(p) != *p {
                    bail!(
                        "view.json: area {}: prefix {p:?} is not a normalised key (it reads as {:?})",
                        a.id,
                        normalise(p)
                    );
                }
            }
            let shape = match a.shape.as_deref() {
                None | Some("any") => AreaShape::Any,
                Some("ext") => AreaShape::Ext,
                Some("shell") => AreaShape::Shell,
                Some(x) => bail!("view.json: area {}: shape {x:?} (any, ext or shell)", a.id),
            };
            list.push(Area { id: a.id, title: a.title, prefixes: a.prefixes, shape, merged: a.merged, local: a.local });
        }
        Ok(Areas { list })
    }

    /// The index of the first area matching `norm`; `list.len()` is [`UNMATCHED`].
    pub fn index_of(&self, norm: &str) -> usize {
        self.list.iter().position(|a| a.matches(norm)).unwrap_or(self.list.len())
    }

    pub fn id(&self, i: usize) -> &str {
        self.list.get(i).map_or(UNMATCHED, |a| a.id.as_str())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Baseline files
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Shipped,
    Local,
}

#[derive(Debug, Clone)]
pub struct SrcLine {
    pub source: String,
    pub status: String,
    pub items: u64,
    pub records: u64,
    pub skipped: u64,
    pub detail: String,
}

/// One baseline file's in-scope keys as normalised text.
#[derive(Debug)]
pub struct KeyFile {
    pub path: PathBuf,
    pub kind: Kind,
    /// `<edition>-<build.ubr>`.
    pub name: String,
    pub header: Vec<String>,
    pub sources: Vec<SrcLine>,
    /// `K`, `V`, `D`, `F` records as written.
    pub counts: [u64; 4],
    pub keys: HashSet<String>,
    /// Truth only: (normalised, as written) of every in-scope key, sorted, one per normalised key.
    pub ordered: Vec<(String, String)>,
    pub out_of_scope: u64,
    pub file_sha256: String,
}

impl KeyFile {
    /// Seal of design §3.4 as the file records it: every one of S1-S4 has exactly one `#src` line, with status ok.
    pub fn incomplete_reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        for want in REQUIRED_SOURCES {
            let lines: Vec<&SrcLine> = self.sources.iter().filter(|s| s.source == want).collect();
            match lines.as_slice() {
                [] => out.push(format!("{want}: no #src line")),
                [one] if one.status == "ok" => {}
                [one] => out.push(format!("{want} {}", one.status)),
                _ => out.push(format!("{want}: more than one #src line")),
            }
        }
        out
    }
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads a baseline file of `want` kind: the shipped `#purge-baseline 1` format, or the local `#purge-baseline-local 1`
/// format with its `#src` lines and a checked `#end` line (a local file without a correct `#end` is refused).
pub fn load(path: &Path, want: Kind, keep_order: bool) -> Result<KeyFile> {
    let file_sha256 = hex(&Sha256::digest(std::fs::read(path).with_context(|| format!("read {}", path.display()))?));
    let mut r = open_text(path)?;
    let mut f = KeyFile {
        path: path.to_path_buf(),
        kind: want,
        name: String::new(),
        header: Vec::new(),
        sources: Vec::new(),
        counts: [0; 4],
        keys: HashSet::new(),
        ordered: Vec::new(),
        out_of_scope: 0,
        file_sha256,
    };
    let mut sha = Sha256::new();
    let mut raw = Vec::new();
    let mut n = 0u64;
    let mut end: Option<(u64, String)> = None;
    let mut originals: Vec<(String, String)> = Vec::new();
    let what = || path.display().to_string();
    loop {
        raw.clear();
        if r.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        n += 1;
        let line = std::str::from_utf8(&raw).with_context(|| format!("{} line {n}: not UTF-8", what()))?;
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        if end.is_some() {
            if body.is_empty() {
                continue;
            }
            bail!("{}: line {n} after the #end line", what());
        }
        if n == 1 {
            let fields: Vec<&str> = body.split('\t').collect();
            let kind = match fields[0] {
                x if x == format!("{LOCAL_TAG} 1") => Kind::Local,
                x if x == format!("{SHIPPED_TAG} 1") => Kind::Shipped,
                x => {
                    bail!("{}: not a baseline header (version 1): {:?}", what(), x.chars().take(80).collect::<String>())
                }
            };
            if kind != want {
                bail!(
                    "{}: a {} baseline where a {} one is needed",
                    what(),
                    if kind == Kind::Local { "local" } else { "shipped" },
                    if want == Kind::Local { "local" } else { "shipped" }
                );
            }
            let need = if kind == Kind::Local { 7 } else { 5 };
            if fields.len() != need {
                bail!("{}: header has {} fields, expected {need}", what(), fields.len());
            }
            f.header = fields[1..].iter().map(|s| s.to_string()).collect();
            f.name = format!("{}-{}", f.header[2], f.header[3]);
            sha.update(&raw);
            continue;
        }
        if let Some(rest) = body.strip_prefix("#end\t") {
            if want != Kind::Local {
                bail!("{}: #end line in a shipped baseline", what());
            }
            let (count, digest) = rest.split_once('\t').with_context(|| format!("{}: bad #end line", what()))?;
            end = Some((count.parse().with_context(|| format!("{}: bad #end count", what()))?, digest.to_string()));
            continue;
        }
        sha.update(&raw);
        if let Some(rest) = body.strip_prefix("#src\t") {
            let p: Vec<&str> = rest.split('\t').collect();
            let [source, status, items, records, skipped, detail] = p.as_slice() else {
                bail!("{}: line {n}: bad #src line", what());
            };
            let num = |s: &str| s.parse::<u64>().with_context(|| format!("{}: line {n}: bad #src count", what()));
            f.sources.push(SrcLine {
                source: source.to_string(),
                status: status.to_string(),
                items: num(items)?,
                records: num(records)?,
                skipped: num(skipped)?,
                detail: unescape(detail),
            });
            continue;
        }
        if body.starts_with('#') || body.is_empty() {
            continue;
        }
        let (tag, rest) = body.split_once('\t').with_context(|| format!("{}: line {n}: no fields", what()))?;
        match tag {
            "K" => {
                f.counts[0] += 1;
                let key = unescape(rest);
                let norm = normalise(&key);
                if !in_scope(&norm) {
                    f.out_of_scope += 1;
                    continue;
                }
                if keep_order {
                    originals.push((norm.clone(), key));
                }
                f.keys.insert(norm);
            }
            "V" => f.counts[1] += 1,
            "D" => f.counts[2] += 1,
            "F" => f.counts[3] += 1,
            other => bail!("{}: line {n}: unknown record type {other:?}", what()),
        }
    }
    if n == 0 {
        bail!("{}: empty file", what());
    }
    if want == Kind::Local {
        let Some((count, digest)) = end else {
            bail!("{}: no #end line (a truncated local baseline is a miss)", what())
        };
        let records: u64 = f.counts.iter().sum();
        if count != records {
            bail!("{}: #end says {count} records, the file has {records}", what());
        }
        let got = hex(&sha.finalize());
        if got != digest {
            bail!("{}: #end sha-256 {digest} does not match the content ({got})", what());
        }
    }
    if keep_order {
        originals.sort();
        originals.dedup_by(|a, b| a.0 == b.0);
        f.ordered = originals;
    }
    Ok(f)
}

// ---------------------------------------------------------------------------------------------------------------
// The diff
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub truth: u64,
    pub covered_local: u64,
    pub covered_merged: u64,
    pub covered_merged_via_twin: u64,
    pub false_absent_local: u64,
    pub false_absent_merged: u64,
    pub shared_local: u64,
    pub shared_merged: u64,
    /// Per [`Shape::ALL`]: (local-only, merged) false-absent keys of that shape.
    pub by_shape: [(u64, u64); 7],
    /// Per set: truth keys it covers, truth keys only it covers, set keys not in truth.
    pub set_covered: Vec<u64>,
    pub set_only: Vec<u64>,
    pub set_extra: Vec<u64>,
    pub extra_merged: u64,
    pub first_local: Vec<String>,
    pub first_merged: Vec<String>,
}

impl Stats {
    fn new(sets: usize) -> Stats {
        Stats { set_covered: vec![0; sets], set_only: vec![0; sets], set_extra: vec![0; sets], ..Stats::default() }
    }
}

/// One shared-shape false-absent key.
#[derive(Debug, Clone)]
pub struct SharedMiss {
    pub key: String,
    pub norm: String,
    pub area: usize,
    pub shape: Shape,
    /// Names of the sets that have it (empty: false absent merged too).
    pub covered_by: Vec<String>,
}

pub struct Diff {
    /// Set names: the local set first, then the neighbours.
    pub sets: Vec<String>,
    pub total: Stats,
    /// One per area, plus [`UNMATCHED`] last.
    pub areas: Vec<Stats>,
    pub shared: Vec<SharedMiss>,
}

fn covers(set: &HashSet<String>, norm: &str, tw: Option<&str>) -> (bool, bool) {
    let exact = set.contains(norm);
    (exact || tw.is_some_and(|t| set.contains(t)), exact)
}

/// The diff of `truth` against `sets` (the local set first).
pub fn diff(truth: &KeyFile, sets: &[&KeyFile], areas: &Areas) -> Diff {
    let ns = sets.len();
    let mut total = Stats::new(ns);
    let mut per: Vec<Stats> = (0..=areas.list.len()).map(|_| Stats::new(ns)).collect();
    let mut shared = Vec::new();
    for (norm, key) in &truth.ordered {
        let ai = areas.index_of(norm);
        let tw = twin(norm);
        let hits: Vec<(bool, bool)> = sets.iter().map(|s| covers(&s.keys, norm, tw.as_deref())).collect();
        let local = hits[0].0;
        let merged = hits.iter().any(|h| h.0);
        let via_twin = merged && !hits.iter().any(|h| h.1);
        let n_hit = hits.iter().filter(|h| h.0).count();
        let sh = shape(norm);
        for st in [&mut total, &mut per[ai]] {
            st.truth += 1;
            st.covered_local += u64::from(local);
            st.covered_merged += u64::from(merged);
            st.covered_merged_via_twin += u64::from(via_twin);
            for (i, h) in hits.iter().enumerate() {
                st.set_covered[i] += u64::from(h.0);
                st.set_only[i] += u64::from(h.0 && n_hit == 1);
            }
            if !local {
                st.false_absent_local += 1;
                if st.first_local.len() < FIRST_N {
                    st.first_local.push(key.clone());
                }
            }
            if !merged {
                st.false_absent_merged += 1;
                if st.first_merged.len() < FIRST_N {
                    st.first_merged.push(key.clone());
                }
            }
            if let Some(s) = sh {
                let k = Shape::ALL.iter().position(|x| *x == s).unwrap_or(0);
                if !local {
                    st.shared_local += 1;
                    st.by_shape[k].0 += 1;
                }
                if !merged {
                    st.shared_merged += 1;
                    st.by_shape[k].1 += 1;
                }
            }
        }
        if let (Some(s), false) = (sh, local) {
            shared.push(SharedMiss {
                key: key.clone(),
                norm: norm.clone(),
                area: ai,
                shape: s,
                covered_by: sets.iter().zip(&hits).filter(|(_, h)| h.0).map(|(f, _)| f.name.clone()).collect(),
            });
        }
    }
    // Extra: set keys that are not truth keys (nor the twin of one); merged counts each key once.
    let in_truth = |k: &str| truth.keys.contains(k) || twin(k).is_some_and(|t| truth.keys.contains(&t));
    for (i, s) in sets.iter().enumerate() {
        for k in &s.keys {
            if in_truth(k) {
                continue;
            }
            let ai = areas.index_of(k);
            let first = !sets[..i].iter().any(|e| e.keys.contains(k));
            for st in [&mut total, &mut per[ai]] {
                st.set_extra[i] += 1;
                st.extra_merged += u64::from(first);
            }
        }
    }
    Diff { sets: sets.iter().map(|s| s.name.clone()).collect(), total, areas: per, shared }
}

fn ratio(a: u64, b: u64) -> Value {
    if b == 0 { Value::Null } else { json!(((a as f64 / b as f64) * 1e6).round() / 1e6) }
}

/// S2 / S3 of design §8.3 for one set: no shared-shape false-absent key and other false-absent keys at most
/// [`OTHER_FALSE_ABSENT_MAX`] of the truth keys. `None` when there are no truth keys.
fn check(truth: u64, false_absent: u64, shared: u64) -> Value {
    if truth == 0 {
        return Value::Null;
    }
    json!(shared == 0 && ((false_absent - shared) as f64) <= OTHER_FALSE_ABSENT_MAX * truth as f64)
}

fn stats_json(st: &Stats, sets: &[String], neighbours: bool, lists: bool) -> Value {
    let per_source: Vec<Value> = sets
        .iter()
        .enumerate()
        .map(|(i, name)| {
            json!({
                "set": name,
                "role": if i == 0 { "local" } else { "neighbour" },
                "covered": st.set_covered[i],
                "only": st.set_only[i],
                "share": ratio(st.set_covered[i], st.covered_merged),
                "extra": st.set_extra[i],
            })
        })
        .collect();
    let mut by_shape = serde_json::Map::new();
    for (k, s) in Shape::ALL.iter().enumerate() {
        by_shape.insert(s.name().into(), json!({"local": st.by_shape[k].0, "merged": st.by_shape[k].1}));
    }
    let mut v = json!({
        "truth": st.truth,
        "covered_local": st.covered_local,
        "covered_merged": st.covered_merged,
        "covered_merged_via_twin": st.covered_merged_via_twin,
        "coverage_local": ratio(st.covered_local, st.truth),
        "coverage_merged": ratio(st.covered_merged, st.truth),
        "false_absent_local": st.false_absent_local,
        "false_absent_merged": st.false_absent_merged,
        "shared_shape_false_absent_local": st.shared_local,
        "shared_shape_false_absent_merged": st.shared_merged,
        "other_false_absent_local": st.false_absent_local - st.shared_local,
        "other_false_absent_merged": st.false_absent_merged - st.shared_merged,
        "shared_shape_by_kind": by_shape,
        "extra_local": st.set_extra.first().copied().unwrap_or(0),
        "extra_merged": st.extra_merged,
        "per_source": per_source,
        "checks": {
            "s3_local": check(st.truth, st.false_absent_local, st.shared_local),
            "s2_merged": if neighbours { check(st.truth, st.false_absent_merged, st.shared_merged) } else { Value::Null },
        },
    });
    if lists {
        v["false_absent_local_first"] = json!(st.first_local);
        v["false_absent_merged_first"] = json!(st.first_merged);
    }
    v
}

fn file_json(f: &KeyFile) -> Value {
    let mut v = json!({
        "path": f.path.display().to_string(),
        "sha256": f.file_sha256,
        "name": f.name,
        "header": f.header,
        "records": {"K": f.counts[0], "V": f.counts[1], "D": f.counts[2], "F": f.counts[3]},
        "keys_in_scope": f.keys.len(),
        "keys_out_of_scope": f.out_of_scope,
    });
    if f.kind == Kind::Local {
        let reasons = f.incomplete_reasons();
        v["complete"] = json!(reasons.is_empty());
        v["incomplete_reasons"] = json!(reasons);
        v["end_check"] = json!("ok");
        v["sources"] = json!(
            f.sources
                .iter()
                .map(|s| json!({"source": s.source, "status": s.status, "items": s.items, "records": s.records,
                                "skipped": s.skipped, "detail": s.detail}))
                .collect::<Vec<_>>()
        );
    }
    v
}

/// The report document.
pub fn report(
    truth: &KeyFile,
    sets: &[&KeyFile],
    areas: &Areas,
    areas_path: &Path,
    areas_sha: &str,
    d: &Diff,
) -> Value {
    let neighbours = sets.len() > 1;
    let mut area_docs = Vec::new();
    for (i, st) in d.areas.iter().enumerate() {
        if i == areas.list.len() && st.truth == 0 && st.set_extra.iter().all(|x| *x == 0) {
            continue;
        }
        let mut v = json!({"id": areas.id(i)});
        if let Some(a) = areas.list.get(i) {
            v["title"] = json!(a.title);
            v["flags"] = json!({"merged": a.merged, "local": a.local});
        }
        if let (Value::Object(m), Value::Object(s)) = (&mut v, stats_json(st, &d.sets, neighbours, true)) {
            m.extend(s);
        }
        area_docs.push(v);
    }
    let shared: Vec<Value> = d
        .shared
        .iter()
        .map(|m| {
            json!({
                "key": m.key,
                "normalised": m.norm,
                "area": areas.id(m.area),
                "shape": m.shape.name(),
                "false_absent": if m.covered_by.is_empty() { "merged" } else { "local_only" },
                "covered_by": m.covered_by,
                "expected_source": expected_source(&m.norm),
            })
        })
        .collect();
    let mut total = stats_json(&d.total, &d.sets, neighbours, false);
    total["checks"]["w1_scope"] = if neighbours {
        json!(d.total.truth > 0 && d.total.covered_merged as f64 >= W1_SCOPE * d.total.truth as f64)
    } else {
        Value::Null
    };
    json!({
        "schema": SCHEMA,
        "rigtool": {"version": env!("CARGO_PKG_VERSION"), "source_sha256": crate::SOURCE_SHA256},
        "inputs": {
            "truth": file_json(truth),
            "local": file_json(sets[0]),
            "neighbours": sets[1..].iter().map(|f| file_json(f)).collect::<Vec<_>>(),
            "areas": {"path": areas_path.display().to_string(), "sha256": areas_sha, "count": areas.list.len()},
        },
        "compared": "K records only, normalised names, inside the capture scope; covered = the set has the key or its 64-bit twin",
        "thresholds": {"other_false_absent_max_share": OTHER_FALSE_ABSENT_MAX, "first_n": FIRST_N,
                       "w1_scope": W1_SCOPE, "w1_area": W1_AREA},
        "sets": d.sets,
        "total": total,
        "areas": area_docs,
        "shared_shape_false_absent": shared,
    })
}

fn pct(a: u64, b: u64) -> String {
    if b == 0 { "-".into() } else { format!("{:.2}", 100.0 * a as f64 / b as f64) }
}

fn summary_line(id: &str, st: &Stats) -> String {
    format!(
        "{id:<28} {:>8} {:>7} {:>7} {:>8} {:>8} {:>6} {:>6} {:>8} {:>8}",
        st.truth,
        pct(st.covered_local, st.truth),
        pct(st.covered_merged, st.truth),
        st.false_absent_local,
        st.false_absent_merged,
        st.shared_local,
        st.shared_merged,
        st.set_extra.first().copied().unwrap_or(0),
        st.extra_merged
    )
}

pub fn cmd_baseline_diff(a: &DiffArgs) -> Result<()> {
    let view_text = jsonio::read_text(&a.areas)?;
    let areas = Areas::parse(&view_text)?;
    let areas_sha = hex(&Sha256::digest(std::fs::read(&a.areas)?));
    let truth = load(&a.truth, Kind::Shipped, true)?;
    let local = load(&a.local, Kind::Local, false)?;
    let mut neighbours = Vec::new();
    for p in &a.neighbours {
        let n = load(p, Kind::Shipped, false)?;
        if n.file_sha256 == truth.file_sha256 || n.name.eq_ignore_ascii_case(&truth.name) {
            bail!("neighbour {} is the truth baseline itself (leave-one-out needs it hidden)", p.display());
        }
        neighbours.push(n);
    }
    let mut sets: Vec<&KeyFile> = vec![&local];
    sets.extend(neighbours.iter());
    let d = diff(&truth, &sets, &areas);
    let doc = report(&truth, &sets, &areas, &a.areas, &areas_sha, &d);
    jsonio::write(&a.out, &doc)?;
    let reasons = local.incomplete_reasons();
    eprintln!(
        "baseline-diff: truth {} ({} keys in scope), local {} ({}; {} keys), neighbours [{}] -> {}",
        truth.name,
        truth.ordered.len(),
        local.name,
        if reasons.is_empty() { "complete".to_string() } else { format!("INCOMPLETE: {}", reasons.join("; ")) },
        local.keys.len(),
        neighbours.iter().map(|n| n.name.as_str()).collect::<Vec<_>>().join(", "),
        a.out.display()
    );
    eprintln!(
        "{:<28} {:>8} {:>7} {:>7} {:>8} {:>8} {:>6} {:>6} {:>8} {:>8}",
        "area", "truth", "loc%", "mrg%", "fa_loc", "fa_mrg", "sh_loc", "sh_mrg", "x_loc", "x_mrg"
    );
    for (i, st) in d.areas.iter().enumerate() {
        if i < areas.list.len() || st.truth > 0 {
            eprintln!("{}", summary_line(areas.id(i), st));
        }
    }
    eprintln!("{}", summary_line("TOTAL", &d.total));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rigtool-bldiff-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn esc(k: &str) -> String {
        crate::escape::escape(k)
    }

    fn shipped(edition: &str, build: &str, keys: &[&str]) -> String {
        let mut t =
            format!("#purge-baseline 1\t2026-11-21T00:00:00Z\tPC\t{edition}\t{build}\n#source\tsnap-0.tsv.gz\n");
        for k in keys {
            t.push_str(&format!("K\t{}\n", esc(k)));
        }
        t.push_str("V\tHKLM\\\\SOFTWARE\\\\X\tv\t1\t0000000000000000\nF\tC:\\\\Windows\\\\notepad.exe\n");
        t
    }

    fn local_text(keys: &[&str], s4: &str) -> String {
        let mut body =
            String::from("#purge-baseline-local 1\t2026-11-21T00:00:00Z\tPC\tProfessional\t26340.9882\tbl.1\tabc\n");
        for s in ["S1", "S2", "S3"] {
            body.push_str(&format!("#src\t{s}\tok\t10\t10\t0\tmanifests=10\n"));
        }
        body.push_str(&format!("#src\tS4\t{s4}\t10\t10\t0\t{}\n", if s4 == "ok" { "" } else { "why=not elevated" }));
        for k in keys {
            body.push_str(&format!("K\t{}\n", esc(k)));
        }
        let digest = hex(&Sha256::digest(body.as_bytes()));
        format!("{body}#end\t{}\t{digest}\n", keys.len())
    }

    fn view() -> Areas {
        Areas::parse(include_str!("../../../kb/baselines/view.json")).unwrap()
    }

    #[test]
    fn normalises_like_the_engine() {
        assert_eq!(normalise("HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo"), "hklm\\software\\foo");
        assert_eq!(
            normalise("HKLM\\SYSTEM\\ControlSet001\\Services\\X"),
            "hklm\\system\\currentcontrolset\\services\\x"
        );
        assert_eq!(normalise("HKU\\S-1-5-21-1-2-3-1001\\Software\\Classes\\.txt"), "hku\\<sid>_classes\\.txt");
        assert_eq!(normalise("HKU\\S-1-5-21-0-0-0-1000_Classes\\CLSID"), "hku\\<sid>_classes\\clsid");
        assert_eq!(normalise("HKU\\S-1-5-18\\Software"), "hku\\.default\\software");
        assert_eq!(
            normalise("HKLM\\SOFTWARE\\WOW6432Node\\Classes\\CLSID"),
            "hklm\\software\\classes\\wow6432node\\clsid"
        );
        assert_eq!(normalise("HKCU\\Software\\X"), "hku\\<sid>\\software\\x");
        assert_eq!(normalise("HKCR\\.txt"), "hklm\\software\\classes\\.txt");
        assert_eq!(fold("A\u{C4}\u{212A}\u{13A0}"), "a\u{E4}\u{212A}\u{13A0}");
        assert_eq!(twin("hklm\\software\\wow6432node\\foo").as_deref(), Some("hklm\\software\\foo"));
        assert_eq!(
            twin("hklm\\software\\classes\\wow6432node\\clsid").as_deref(),
            Some("hklm\\software\\classes\\clsid")
        );
        assert_eq!(twin("hklm\\software\\foo"), None);
        assert!(
            in_scope("hklm\\software\\x") && in_scope("hku\\.default") && in_scope("hklm\\system\\currentcontrolset")
        );
        assert!(!in_scope("hklm\\system\\currentcontrolset\\enum\\pci") && !in_scope("hklm\\system\\setup"));
        assert!(!in_scope("hklm\\system\\currentcontrolset\\control\\deviceclasses\\x") && !in_scope("hklm\\sam"));
    }

    #[test]
    fn shape_classifier() {
        let s = |k: &str| shape(&normalise(k));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\.txt"), Some(Shape::Ext));
        assert_eq!(s("HKU\\S-1-5-21-1-2-3-1001_Classes\\.log"), Some(Shape::Ext));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\WOW6432Node\\.txt"), Some(Shape::Ext));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\.txt\\OpenWithProgids"), Some(Shape::ExtOpenWithProgids));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\.txt\\OpenWithList"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\txtfile\\shell"), Some(Shape::Shell));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\*\\shell"), Some(Shape::Shell));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\.txt\\shell"), Some(Shape::Shell));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\txtfile\\shell\\open"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\*\\shellex"), Some(Shape::Shellex));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers"), Some(Shape::Shellex));
        assert_eq!(
            s("HKLM\\SOFTWARE\\Classes\\Directory\\Background\\shellex\\ContextMenuHandlers"),
            Some(Shape::Shellex)
        );
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\7-Zip"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\txtfile"), Some(Shape::ProgId));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\Word.Document.12"), Some(Shape::ProgId));
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\CLSID"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\Local Settings"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Classes"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Mozilla"), Some(Shape::VendorDepth1));
        assert_eq!(s("HKLM\\SOFTWARE\\Mozilla\\Firefox"), Some(Shape::VendorDepth2));
        assert_eq!(s("HKLM\\SOFTWARE\\Mozilla\\Firefox\\1.0"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\WOW6432Node\\Mozilla"), Some(Shape::VendorDepth1));
        assert_eq!(s("HKLM\\SOFTWARE\\WOW6432Node\\Mozilla\\Firefox"), Some(Shape::VendorDepth2));
        assert_eq!(s("HKLM\\SOFTWARE\\WOW6432Node"), None);
        assert_eq!(s("HKLM\\SOFTWARE\\Microsoft"), Some(Shape::VendorDepth1));
        assert_eq!(s("HKU\\S-1-5-21-1-2-3-1001\\Software\\7-Zip"), Some(Shape::VendorDepth1));
        assert_eq!(s("HKLM\\SOFTWARE"), None);
        assert_eq!(s("HKLM\\SYSTEM\\CurrentControlSet\\Services\\X"), None);
    }

    #[test]
    fn view_json_areas() {
        let a = view();
        let id = |k: &str| a.id(a.index_of(&normalise(k))).to_string();
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\CLSID\\{X}\\InprocServer32"), "classes-clsid");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\Interface\\{X}"), "classes-interface");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\TypeLib\\{X}"), "classes-typelib");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\AppID\\{X}"), "classes-appid");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\.txt\\OpenWithProgids"), "classes-ext");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\.txt\\shell\\open"), "classes-shell");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\txtfile\\shell\\open\\command"), "classes-shell");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers"), "classes-shell");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\txtfile\\DefaultIcon"), "classes-progid");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes"), "classes-progid");
        assert_eq!(id("HKLM\\SOFTWARE\\Classes\\WOW6432Node\\CLSID\\{X}"), "classes-wow6432node");
        assert_eq!(id("HKLM\\SOFTWARE\\WOW6432Node\\Classes\\CLSID\\{X}"), "classes-wow6432node");
        assert_eq!(id("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), "software-ms-currentversion");
        assert_eq!(id("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), "software-microsoft");
        assert_eq!(id("HKLM\\SOFTWARE\\Mozilla"), "software-vendor");
        assert_eq!(id("HKLM\\SOFTWARE"), "software-vendor");
        assert_eq!(id("HKLM\\SOFTWARE\\WOW6432Node\\Mozilla"), "software-wow6432node");
        assert_eq!(id("HKLM\\SOFTWARE\\Clients\\StartMenuInternet"), "software-clients");
        assert_eq!(id("HKLM\\SOFTWARE\\RegisteredApplications"), "software-clients");
        assert_eq!(id("HKLM\\SOFTWARE\\WOW6432Node\\Clients\\Mail"), "software-clients");
        assert_eq!(id("HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip"), "system-services");
        assert_eq!(id("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"), "system-control");
        assert_eq!(id("HKLM\\SYSTEM\\CurrentControlSet\\Hardware Profiles"), "system");
        assert_eq!(id("HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows"), "hku-software-microsoft");
        assert_eq!(id("HKU\\S-1-5-21-1-2-3-1001\\Software\\7-Zip"), "hku-software");
        assert_eq!(id("HKU\\S-1-5-21-1-2-3-1001\\Control Panel\\Desktop"), "hku-profile");
        assert_eq!(id("HKU\\S-1-5-21-1-2-3-1001\\Software\\Classes\\.txt"), "hku-classes");
        assert_eq!(id("HKU\\S-1-5-21-1-2-3-1001_Classes\\CLSID"), "hku-classes");
        assert_eq!(id("HKU\\.DEFAULT\\Software\\Microsoft"), "hku-default");
        assert_eq!(id("HKU\\S-1-5-18\\Control Panel"), "hku-default");
        assert_eq!(id("HKU\\S-1-5-19\\Software"), "hku-other");
        // The flags gate M (BL-MEASURE round 2, review BL-RM) set: merged in seven areas, local nowhere.
        let merged: Vec<&str> = a.list.iter().filter(|x| x.merged).map(|x| x.id.as_str()).collect();
        assert_eq!(
            merged,
            [
                "classes-wow6432node",
                "classes-clsid",
                "classes-interface",
                "classes-appid",
                "software-clients",
                "software-wow6432node",
                "software-vendor"
            ]
        );
        assert!(a.list.iter().all(|x| !x.local), "no area is marked local (gate M)");
    }

    #[test]
    fn bad_view_files_are_refused() {
        let wrap = |areas: &str| format!("{{\"schema\":\"{VIEW_SCHEMA}\",\"areas\":[{areas}]}}");
        assert!(Areas::parse(&wrap(r#"{"id":"a","prefixes":["hklm\\software"]}"#)).is_ok());
        assert!(Areas::parse(&wrap(r#"{"id":"a","prefixes":["HKLM\\SOFTWARE"]}"#)).is_err());
        assert!(Areas::parse(&wrap(r#"{"id":"a","prefixes":[]}"#)).is_err());
        assert!(Areas::parse(&wrap(r#"{"id":"a","prefixes":["hklm"],"shape":"odd"}"#)).is_err());
        assert!(Areas::parse(&wrap(r#"{"id":"a","prefixes":["hklm"]},{"id":"a","prefixes":["hku"]}"#)).is_err());
        assert!(Areas::parse(&wrap(r#"{"id":"a","prefixes":["hklm"],"typo":1}"#)).is_err());
        assert!(Areas::parse(r#"{"schema":"x","areas":[]}"#).is_err());
    }

    #[test]
    fn local_files_are_checked() {
        let d = tmpdir("seal");
        let p = d.join("local.tsv");
        std::fs::write(&p, local_text(&["HKLM\\SOFTWARE\\A"], "ok")).unwrap();
        let f = load(&p, Kind::Local, false).unwrap();
        assert!(f.incomplete_reasons().is_empty());
        assert_eq!(f.name, "Professional-26340.9882");
        assert!(load(&p, Kind::Shipped, false).unwrap_err().0.contains("a local baseline where a shipped one"));
        std::fs::write(&p, local_text(&["HKLM\\SOFTWARE\\A"], "incomplete")).unwrap();
        assert_eq!(load(&p, Kind::Local, false).unwrap().incomplete_reasons(), vec!["S4 incomplete"]);
        let good = local_text(&["HKLM\\SOFTWARE\\A", "HKLM\\SOFTWARE\\B"], "ok");
        // A changed record, a wrong count, a missing #end, a line after #end: each a miss.
        std::fs::write(&p, good.replace("SOFTWARE\\\\B", "SOFTWARE\\\\C")).unwrap();
        assert!(load(&p, Kind::Local, false).unwrap_err().0.contains("does not match"));
        std::fs::write(&p, good.replace("#end\t2", "#end\t3")).unwrap();
        assert!(load(&p, Kind::Local, false).unwrap_err().0.contains("#end says 3"));
        std::fs::write(&p, good.lines().filter(|l| !l.starts_with("#end")).collect::<Vec<_>>().join("\n")).unwrap();
        assert!(load(&p, Kind::Local, false).unwrap_err().0.contains("no #end"));
        std::fs::write(&p, format!("{good}K\tHKLM\\\\SOFTWARE\\\\Z\n")).unwrap();
        assert!(load(&p, Kind::Local, false).unwrap_err().0.contains("after the #end"));
        let s = d.join("s.tsv");
        std::fs::write(&s, shipped("Professional", "26340.9882", &["HKLM\\SOFTWARE\\A"])).unwrap();
        assert!(load(&s, Kind::Local, false).unwrap_err().0.contains("a shipped baseline where a local one"));
        std::fs::remove_dir_all(&d).ok();
    }

    /// Synthetic truth, local and neighbour files with known counts per area.
    #[test]
    fn synthetic_counts_per_area() {
        let d = tmpdir("counts");
        let sid = "S-1-5-21-111-222-333-1001";
        let truth_keys: Vec<String> = [
            // classes-clsid: 4 truth keys; local has 3 (CLSID, A, B), neighbour has C.
            "HKLM\\SOFTWARE\\Classes\\CLSID",
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{A}",
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{B}",
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{C}",
            // classes-ext: .txt (local), .txt\OpenWithProgids (neighbour only), .log (nowhere: shared, merged).
            "HKLM\\SOFTWARE\\Classes\\.txt",
            "HKLM\\SOFTWARE\\Classes\\.txt\\OpenWithProgids",
            "HKLM\\SOFTWARE\\Classes\\.log",
            // software-wow6432node: covered through the 64-bit twin in local.
            "HKLM\\SOFTWARE\\WOW6432Node\\Foo",
            // hku-classes: one key, in nobody (not shared: depth 2 below CLSID).
            &format!("HKU\\{sid}_Classes\\CLSID\\{{D}}"),
            // hku-software-microsoft: in both local and neighbour.
            &format!("HKU\\{sid}\\Software\\Microsoft\\Notepad"),
            // out of scope: dropped.
            "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let tk: Vec<&str> = truth_keys.iter().map(String::as_str).collect();
        std::fs::write(d.join("truth.tsv"), shipped("Professional", "26340.9882", &tk)).unwrap();
        let lk = [
            "HKLM\\SOFTWARE\\Classes\\CLSID",
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{A}",
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{B}",
            "HKLM\\SOFTWARE\\Classes\\.txt",
            "HKLM\\SOFTWARE\\Foo",
            "HKU\\S-1-5-21-0-0-0-1000\\Software\\Microsoft\\Notepad",
            // extra in local: CLSID\{E} (classes-clsid) and Contoso (software-vendor); HKLM\SOFTWARE\Foo is extra too.
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{E}",
            "HKLM\\SOFTWARE\\Contoso",
        ];
        std::fs::write(d.join("local.tsv"), local_text(&lk, "ok")).unwrap();
        let nk = [
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{C}",
            "HKLM\\SOFTWARE\\Classes\\.txt\\OpenWithProgids",
            &format!("HKU\\{sid}\\Software\\Microsoft\\Notepad"),
            // extra: one shared with local ({E}), one of its own.
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{E}",
            "HKLM\\SOFTWARE\\Classes\\CLSID\\{F}",
        ];
        std::fs::write(d.join("nb.tsv"), shipped("EnterpriseS", "26100.1742", &nk)).unwrap();
        std::fs::write(d.join("view.json"), include_str!("../../../kb/baselines/view.json")).unwrap();
        let out = d.join("report.json");
        cmd_baseline_diff(&DiffArgs {
            truth: d.join("truth.tsv"),
            local: d.join("local.tsv"),
            neighbours: vec![d.join("nb.tsv")],
            areas: d.join("view.json"),
            out: out.clone(),
        })
        .unwrap();
        let r: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(r["schema"], SCHEMA);
        assert_eq!(r["sets"], json!(["Professional-26340.9882", "EnterpriseS-26100.1742"]));
        assert_eq!(r["inputs"]["truth"]["keys_out_of_scope"], 1);
        assert_eq!(r["inputs"]["local"]["complete"], true);
        let t = &r["total"];
        assert_eq!(t["truth"], 10);
        assert_eq!(t["covered_local"], 6);
        assert_eq!(t["covered_merged"], 8);
        assert_eq!(t["covered_merged_via_twin"], 1);
        assert_eq!(t["false_absent_local"], 4);
        assert_eq!(t["false_absent_merged"], 2);
        assert_eq!(t["shared_shape_false_absent_local"], 2);
        assert_eq!(t["shared_shape_false_absent_merged"], 1);
        assert_eq!(t["shared_shape_by_kind"]["ext"], json!({"local": 1, "merged": 1}));
        assert_eq!(t["shared_shape_by_kind"]["ext_openwithprogids"], json!({"local": 1, "merged": 0}));
        // Local's extra keys: CLSID\{E}, Contoso and the 64-bit Foo (truth has only the 32-bit one).
        assert_eq!(t["extra_local"], 3);
        assert_eq!(t["extra_merged"], 4);
        assert_eq!(t["per_source"][0]["covered"], 6);
        assert_eq!(t["per_source"][0]["only"], 5);
        assert_eq!(t["per_source"][1]["covered"], 3);
        assert_eq!(t["per_source"][1]["only"], 2);
        assert_eq!(t["per_source"][1]["extra"], 2);
        assert_eq!(t["checks"]["w1_scope"], false);
        let area = |id: &str| r["areas"].as_array().unwrap().iter().find(|a| a["id"] == id).unwrap().clone();
        let c = area("classes-clsid");
        assert_eq!(
            (c["truth"].clone(), c["covered_local"].clone(), c["covered_merged"].clone()),
            (json!(4), json!(3), json!(4))
        );
        assert_eq!(c["false_absent_local_first"], json!(["HKLM\\SOFTWARE\\Classes\\CLSID\\{C}"]));
        assert_eq!(c["false_absent_merged_first"], json!([]));
        assert_eq!((c["extra_local"].clone(), c["extra_merged"].clone()), (json!(1), json!(2)));
        assert_eq!(c["checks"]["s2_merged"], true);
        assert_eq!(c["checks"]["s3_local"], false);
        assert_eq!(c["flags"], json!({"merged": true, "local": false}));
        let e = area("classes-ext");
        assert_eq!(
            (e["truth"].clone(), e["covered_local"].clone(), e["covered_merged"].clone()),
            (json!(3), json!(1), json!(2))
        );
        assert_eq!(e["false_absent_merged_first"], json!(["HKLM\\SOFTWARE\\Classes\\.log"]));
        assert_eq!(e["checks"]["s2_merged"], false);
        let w = area("software-wow6432node");
        assert_eq!((w["covered_local"].clone(), w["covered_merged_via_twin"].clone()), (json!(1), json!(1)));
        assert_eq!(area("hku-classes")["false_absent_merged"], 1);
        assert_eq!(area("hku-classes")["shared_shape_false_absent_merged"], 0);
        assert_eq!(area("hku-software-microsoft")["covered_local"], 1);
        assert_eq!(area("software-vendor")["truth"], 0);
        assert_eq!(area("software-vendor")["extra_local"], 2);
        assert_eq!(area("software-vendor")["coverage_local"], Value::Null);
        let shared = r["shared_shape_false_absent"].as_array().unwrap();
        assert_eq!(shared.len(), 2);
        assert_eq!(shared[0]["key"], "HKLM\\SOFTWARE\\Classes\\.log");
        assert_eq!(shared[0]["false_absent"], "merged");
        assert_eq!(shared[1]["shape"], "ext_openwithprogids");
        assert_eq!(shared[1]["covered_by"], json!(["EnterpriseS-26100.1742"]));
        assert!(r["areas"].as_array().unwrap().iter().all(|a| a["id"] != UNMATCHED));

        // Local only: no neighbour, merged equals local and the S2 check is not answered.
        cmd_baseline_diff(&DiffArgs {
            truth: d.join("truth.tsv"),
            local: d.join("local.tsv"),
            neighbours: vec![],
            areas: d.join("view.json"),
            out: out.clone(),
        })
        .unwrap();
        let r: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(r["total"]["covered_merged"], 6);
        assert_eq!(r["total"]["checks"]["s2_merged"], Value::Null);
        assert_eq!(r["total"]["checks"]["w1_scope"], Value::Null);
        assert_eq!(r["shared_shape_false_absent"].as_array().unwrap().len(), 2);

        // The truth itself as a neighbour is refused (leave-one-out).
        let err = cmd_baseline_diff(&DiffArgs {
            truth: d.join("truth.tsv"),
            local: d.join("local.tsv"),
            neighbours: vec![d.join("truth.tsv")],
            areas: d.join("view.json"),
            out,
        })
        .unwrap_err();
        assert!(err.0.contains("leave-one-out"), "{}", err.0);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn first_n_is_capped_and_gz_is_read() {
        let d = tmpdir("cap");
        let keys: Vec<String> = (0..250).map(|i| format!("HKLM\\SOFTWARE\\Classes\\CLSID\\{{{i:04}}}")).collect();
        let tk: Vec<&str> = keys.iter().map(String::as_str).collect();
        let gz = |text: String, p: &Path| {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(text.as_bytes()).unwrap();
            std::fs::write(p, e.finish().unwrap()).unwrap();
        };
        gz(shipped("Professional", "26340.9882", &tk), &d.join("t.tsv.gz"));
        gz(local_text(&["HKLM\\SOFTWARE\\Classes\\CLSID"], "ok"), &d.join("l.tsv.gz"));
        let truth = load(&d.join("t.tsv.gz"), Kind::Shipped, true).unwrap();
        let local = load(&d.join("l.tsv.gz"), Kind::Local, false).unwrap();
        let x = diff(&truth, &[&local], &view());
        let ai = view().list.iter().position(|a| a.id == "classes-clsid").unwrap();
        assert_eq!(x.areas[ai].false_absent_local, 250);
        assert_eq!(x.areas[ai].first_local.len(), FIRST_N);
        assert_eq!(x.areas[ai].first_local[0], "HKLM\\SOFTWARE\\Classes\\CLSID\\{0000}");
        std::fs::remove_dir_all(&d).ok();
    }
}
