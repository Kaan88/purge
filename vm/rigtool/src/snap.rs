//! Snapshot format (RIG.md §2): records, streaming reader, in-memory index, writer helpers.

use crate::canon::{self, CiStr, CiString};
use crate::escape::{escape_into, unescape};
use crate::err::{Context, Result, bail};
use flate2::read::MultiGzDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub const MAGIC: &str = "#purge-snap 1";
pub const PREVIEW_MAX: usize = 1024;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Header {
    pub time: String,
    pub computer: String,
    pub edition: String,
    pub build: String,
}

/// One capture root. `depth1` = entries directly inside only.
#[derive(Clone, Debug, PartialEq)]
pub struct RootSpec {
    pub reg: bool,
    pub path: String,
    pub depth1: bool,
}

impl RootSpec {
    /// Parse a `--root` spec: path or registry key, optional `@1` suffix. `sid` maps HKCU.
    pub fn parse(spec: &str, sid: Option<&str>) -> RootSpec {
        let (body, depth1) = match spec.strip_suffix("@1") {
            Some(b) => (b, true),
            None => (spec, false),
        };
        let body = expand_env(body);
        if canon::looks_like_reg(&body) {
            RootSpec { reg: true, path: canon::canon_reg(&body, sid), depth1 }
        } else {
            RootSpec { reg: false, path: canon::canon_path(&body), depth1 }
        }
    }
    pub fn spec_string(&self) -> String {
        if self.depth1 { format!("{}@1", self.path) } else { self.path.clone() }
    }
    /// Would a capture of this root record `p` (a key for reg roots, a path for fs roots)?
    pub fn captures(&self, p: &str) -> bool {
        if self.depth1 {
            canon::ci_eq(p, &self.path) || canon::parent(p).is_some_and(|q| canon::ci_eq(q, &self.path))
        } else {
            canon::is_under_or_eq(p, &self.path)
        }
    }
}

/// Expand `%VAR%` references from the environment.
pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) => {
                let name = &after[..j];
                match std::env::var(name) {
                    Ok(v) if !name.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[j + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[derive(Clone, Debug, PartialEq)]
pub struct FsRec {
    pub dir: bool,
    pub size: u64,
    pub attrs: u32,
    pub mtime: u64,
    pub reparse: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValRec {
    pub name: String,
    pub typ: u32,
    pub len: u32,
    pub hash: u64,
    pub preview: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeyRec {
    pub lwt: u64,
    /// None when the key could not be opened (counts unknown).
    pub nv: Option<u32>,
    pub ns: Option<u32>,
    /// Sorted case-insensitively by name.
    pub values: Vec<ValRec>,
    /// True if a K record was seen (false = only V records referenced it).
    pub seen: bool,
}

impl KeyRec {
    pub fn value(&self, name: &str) -> Option<&ValRec> {
        self.values
            .binary_search_by(|v| canon::ci_cmp(&v.name, name))
            .ok()
            .map(|i| &self.values[i])
    }
}

/// One parsed line.
#[derive(Clone, Debug)]
pub enum Rec {
    Header(Header),
    Meta(String, Vec<String>),
    D { path: String, attrs: u32, mtime: u64, reparse: u32 },
    F { path: String, size: u64, attrs: u32, mtime: u64, reparse: u32 },
    K { key: String, lwt: u64, nv: Option<u32>, ns: Option<u32> },
    V { key: String, name: String, typ: u32, len: u32, hash: u64, preview: String },
}

fn hex32(s: &str) -> Result<u32> {
    let t = s.trim_start_matches("0x");
    Ok(u32::from_str_radix(if t.is_empty() { "0" } else { t }, 16)?)
}
fn hex64(s: &str) -> Result<u64> {
    let t = s.trim_start_matches("0x");
    Ok(u64::from_str_radix(if t.is_empty() { "0" } else { t }, 16)?)
}
fn opt_u32(s: &str) -> Result<Option<u32>> {
    if s.is_empty() { Ok(None) } else { Ok(Some(s.parse()?)) }
}

/// Parse one line (without the trailing newline). `previews=false` drops value previews.
pub fn parse_line(line: &str, previews: bool) -> Result<Option<Rec>> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Ok(None);
    }
    let f: Vec<&str> = line.split('\t').collect();
    if line.starts_with('#') {
        if f[0] == "#purge-snap 1" || f[0] == "#purge-baseline 1" {
            let g = |i: usize| f.get(i).map(|s| unescape(s)).unwrap_or_default();
            return Ok(Some(Rec::Header(Header { time: g(1), computer: g(2), edition: g(3), build: g(4) })));
        }
        return Ok(Some(Rec::Meta(f[0][1..].to_string(), f[1..].iter().map(|s| unescape(s)).collect())));
    }
    let need = |n: usize| -> Result<()> {
        if f.len() < n {
            bail!("short record ({} fields, want {n}): {}", f.len(), line.chars().take(200).collect::<String>());
        }
        Ok(())
    };
    Ok(Some(match f[0] {
        "D" => {
            need(5)?;
            Rec::D { path: unescape(f[1]), attrs: hex32(f[2])?, mtime: f[3].parse()?, reparse: hex32(f[4])? }
        }
        "F" => {
            need(6)?;
            Rec::F {
                path: unescape(f[1]),
                size: f[2].parse()?,
                attrs: hex32(f[3])?,
                mtime: f[4].parse()?,
                reparse: hex32(f[5])?,
            }
        }
        "K" => {
            need(5)?;
            Rec::K { key: unescape(f[1]), lwt: f[2].parse()?, nv: opt_u32(f[3])?, ns: opt_u32(f[4])? }
        }
        "V" => {
            need(6)?;
            Rec::V {
                key: unescape(f[1]),
                name: unescape(f[2]),
                typ: f[3].parse()?,
                len: f[4].parse()?,
                hash: hex64(f[5])?,
                preview: if previews { f.get(6).map(|s| unescape(s)).unwrap_or_default() } else { String::new() },
            }
        }
        other => bail!("unknown record type {other:?}"),
    }))
}

pub fn open_text(path: &Path) -> Result<Box<dyn BufRead>> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0u8; 2];
    let n = f.read(&mut magic)?;
    drop(f);
    let f = File::open(path)?;
    if n == 2 && magic == [0x1f, 0x8b] {
        Ok(Box::new(BufReader::with_capacity(1 << 20, MultiGzDecoder::new(BufReader::with_capacity(1 << 20, f)))))
    } else {
        Ok(Box::new(BufReader::with_capacity(1 << 20, f)))
    }
}

/// Stream every record of a snap file.
pub fn for_each_rec(path: &Path, previews: bool, mut cb: impl FnMut(Rec) -> Result<()>) -> Result<()> {
    let mut r = open_text(path)?;
    let mut line = String::new();
    let mut n = 0usize;
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        n += 1;
        let l = line.strip_suffix('\n').unwrap_or(&line);
        if let Some(rec) = parse_line(l, previews).with_context(|| format!("{}:{n}", path.display()))? {
            cb(rec)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct LoadOpts {
    pub values: bool,
    pub previews: bool,
}
impl Default for LoadOpts {
    fn default() -> Self {
        LoadOpts { values: true, previews: true }
    }
}

/// In-memory, case-insensitively indexed snapshot.
#[derive(Default)]
pub struct Snap {
    pub header: Header,
    pub roots: Vec<RootSpec>,
    pub excludes: Vec<String>,
    pub fs: HashMap<CiString, FsRec>,
    pub keys: HashMap<CiString, KeyRec>,
    pub errors: u64,
    pub error_paths: Vec<String>,
    pub n_values: usize,
    /// `#denied` lines: keys/dirs whose listing (subkeys, values or entries) failed or is incomplete.
    pub denied: std::collections::HashSet<CiString>,
    /// K/V records dropped because they lie below `HKU\S-1-5-18` (older snaps followed that link and
    /// captured `HKU\.DEFAULT` a second time).
    pub alias_dropped: u64,
}

/// `HKU\S-1-5-18\…` (strictly below): a followed link to `HKU\.DEFAULT`.
fn below_s1518_alias(key: &str) -> bool {
    const P: &[u8] = b"HKU\\S-1-5-18\\";
    let b = key.as_bytes();
    b.len() > P.len() && b[..P.len()].eq_ignore_ascii_case(P)
}

impl Snap {
    pub fn load(path: &Path, opts: LoadOpts) -> Result<Snap> {
        let mut s = Snap::default();
        for_each_rec(path, opts.previews, |r| {
            s.add(r, opts.values);
            Ok(())
        })?;
        s.finish();
        Ok(s)
    }

    #[cfg(test)]
    pub fn from_text(text: &str) -> Result<Snap> {
        let mut s = Snap::default();
        for l in text.lines() {
            if let Some(r) = parse_line(l, true)? {
                s.add(r, true);
            }
        }
        s.finish();
        Ok(s)
    }

    pub fn add(&mut self, r: Rec, values: bool) {
        match r {
            Rec::Header(h) => self.header = h,
            Rec::Meta(tag, f) => match tag.as_str() {
                "errors" => {
                    self.errors = f.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                    if let Some(p) = f.get(1) {
                        self.error_paths = p.split('|').filter(|s| !s.is_empty()).map(str::to_string).collect();
                    }
                }
                "roots" => {
                    self.roots = f.iter().filter(|s| !s.is_empty()).map(|s| RootSpec::parse(s, None)).collect()
                }
                "exclude" => self.excludes = f.iter().filter(|s| !s.is_empty()).cloned().collect(),
                "denied" => {
                    if let Some(p) = f.first().filter(|s| !s.is_empty()) {
                        self.denied.insert(CiString(p.clone()));
                    }
                }
                _ => {}
            },
            Rec::K { key, .. } | Rec::V { key, .. } if below_s1518_alias(&key) => {
                self.alias_dropped += 1;
            }
            Rec::D { path, attrs, mtime, reparse } => {
                self.fs.insert(CiString(path), FsRec { dir: true, size: 0, attrs, mtime, reparse });
            }
            Rec::F { path, size, attrs, mtime, reparse } => {
                self.fs.insert(CiString(path), FsRec { dir: false, size, attrs, mtime, reparse });
            }
            Rec::K { key, lwt, nv, ns } => {
                let e = self.keys.entry(CiString(key)).or_default();
                e.lwt = lwt;
                e.nv = nv;
                e.ns = ns;
                e.seen = true;
            }
            Rec::V { key, name, typ, len, hash, preview } => {
                if !values {
                    return;
                }
                self.n_values += 1;
                let v = ValRec { name, typ, len, hash, preview };
                if let Some(k) = self.keys.get_mut(CiStr::new(&key)) {
                    k.values.push(v);
                } else {
                    let k = KeyRec { values: vec![v], ..Default::default() };
                    self.keys.insert(CiString(key), k);
                }
            }
        }
    }

    pub fn finish(&mut self) {
        for k in self.keys.values_mut() {
            if k.values.len() > 1 {
                k.values.sort_by(|a, b| canon::ci_cmp(&a.name, &b.name));
            }
        }
    }

    pub fn has_path(&self, p: &str) -> bool {
        self.fs.contains_key(CiStr::new(p))
    }
    pub fn path(&self, p: &str) -> Option<&FsRec> {
        self.fs.get(CiStr::new(p))
    }
    pub fn has_key(&self, k: &str) -> bool {
        self.keys.get(CiStr::new(k)).is_some_and(|r| r.seen)
    }
    pub fn key(&self, k: &str) -> Option<&KeyRec> {
        self.keys.get(CiStr::new(k)).filter(|r| r.seen)
    }
    pub fn value(&self, k: &str, name: &str) -> Option<&ValRec> {
        self.keys.get(CiStr::new(k))?.value(name)
    }

    pub fn is_denied(&self, p: &str) -> bool {
        !self.denied.is_empty() && self.denied.contains(CiStr::new(p))
    }

    /// Would this capture have recorded path `p` if it existed?
    pub fn captures_path(&self, p: &str) -> bool {
        if self.roots.is_empty() {
            return self.has_path(p) || canon::parent(p).is_some_and(|q| self.has_path(q) && !self.is_denied(q));
        }
        let Some(root) = self.roots.iter().filter(|r| !r.reg && r.captures(p)).max_by_key(|r| r.path.len()) else {
            return false;
        };
        // An ancestor (up to the root) whose listing failed hides p; an ancestor strictly between the root
        // and p that is a reparse point is never traversed.
        for a in canon::ancestors(p) {
            if a.len() < root.path.len() {
                break;
            }
            if self.is_denied(a) {
                return false;
            }
            if canon::ci_eq(a, &root.path) {
                break;
            }
            if let Some(r) = self.path(a)
                && r.reparse != 0
            {
                return false;
            }
        }
        true
    }

    /// Would this capture have recorded key `k` if it existed? Not when an ancestor (up to the root)
    /// could not be opened or queried (`K` record without counts) or its listing failed (`#denied`).
    pub fn captures_key(&self, k: &str) -> bool {
        if self.excludes.iter().any(|x| canon::is_under_or_eq(k, x)) {
            return false;
        }
        let readable = |a: &str| !self.is_denied(a) && self.key(a).is_none_or(|r| r.nv.is_some());
        if self.roots.is_empty() {
            return self.keys.contains_key(CiStr::new(k)) || canon::parent(k).is_some_and(|q| self.has_key(q) && readable(q));
        }
        let Some(root) = self.roots.iter().filter(|r| r.reg && r.captures(k)).max_by_key(|r| r.path.len()) else {
            return false;
        };
        for a in canon::ancestors(k) {
            if a.len() < root.path.len() {
                break;
            }
            if !readable(a) {
                return false;
            }
            if canon::ci_eq(a, &root.path) {
                break;
            }
        }
        true
    }

    /// Values of key `k` were fully listed (the key was read and its listing did not fail).
    pub fn values_known(&self, k: &str) -> bool {
        // A child of an `@1` registry root is recorded as a key only (its K record still carries the
        // value count, but no V records were written), so its values are unknown.
        let depth1_child = self.roots.iter().any(|r| {
            r.reg && r.depth1 && !canon::ci_eq(k, &r.path) && canon::parent(k).is_some_and(|q| canon::ci_eq(q, &r.path))
        }) && !self.roots.iter().any(|r| r.reg && !r.depth1 && r.captures(k));
        if depth1_child {
            return false;
        }
        match self.key(k) {
            Some(r) => r.nv.is_some() && !self.is_denied(k),
            None => self.captures_key(k),
        }
    }

    /// Registry symbolic links this snap recorded: (link key, canonical target).
    pub fn reg_links(&self) -> Vec<(String, String)> {
        self.keys
            .iter()
            .filter_map(|(k, r)| {
                let v = r.value("SymbolicLinkValue")?;
                if v.typ != REG_LINK || v.preview.is_empty() {
                    return None;
                }
                Some((k.0.clone(), canon::canon_reg(&v.preview, None)))
            })
            .collect()
    }

    /// The interactive user's SID: the first `HKU\S-1-5-21-…` that also has a `_Classes` hive, else
    /// the only `S-1-5-21-…` SID that appears under `HKU` at all.
    pub fn guess_user_sid(&self) -> Option<String> {
        let mut all = std::collections::BTreeSet::new();
        for k in self.keys.keys() {
            let Some(rest) = k.as_str().strip_prefix("HKU\\") else { continue };
            let s = rest.split('\\').next().unwrap_or("");
            if s.starts_with("S-1-5-21-") && !s.to_ascii_lowercase().ends_with("_classes") {
                all.insert(s.to_string());
            }
        }
        if let Some(s) = all.iter().find(|s| self.has_key(&format!("HKU\\{s}_Classes"))) {
            return Some(s.clone());
        }
        if all.len() == 1 { all.into_iter().next() } else { None }
    }
}

// ---------------------------------------------------------------------------------------------
// Writer helpers
// ---------------------------------------------------------------------------------------------

pub fn header_line(h: &Header) -> String {
    let mut s = String::from(MAGIC);
    for f in [&h.time, &h.computer, &h.edition, &h.build] {
        s.push('\t');
        escape_into(f, &mut s);
    }
    s.push('\n');
    s
}

pub fn meta_line(tag: &str, fields: &[String]) -> String {
    let mut s = format!("#{tag}");
    for f in fields {
        s.push('\t');
        escape_into(f, &mut s);
    }
    s.push('\n');
    s
}

pub fn write_d(out: &mut String, path: &str, attrs: u32, mtime: u64, reparse: u32) {
    out.push_str("D\t");
    escape_into(path, out);
    use std::fmt::Write;
    let _ = writeln!(out, "\t{attrs:x}\t{mtime}\t{reparse:x}");
}

pub fn write_f(out: &mut String, path: &str, size: u64, attrs: u32, mtime: u64, reparse: u32) {
    out.push_str("F\t");
    escape_into(path, out);
    use std::fmt::Write;
    let _ = writeln!(out, "\t{size}\t{attrs:x}\t{mtime}\t{reparse:x}");
}

pub fn write_k(out: &mut String, key: &str, lwt: u64, nv: Option<u32>, ns: Option<u32>) {
    out.push_str("K\t");
    escape_into(key, out);
    use std::fmt::Write;
    let _ = write!(out, "\t{lwt}\t");
    if let Some(n) = nv {
        let _ = write!(out, "{n}");
    }
    out.push('\t');
    if let Some(n) = ns {
        let _ = write!(out, "{n}");
    }
    out.push('\n');
}

pub fn write_v(out: &mut String, key: &str, name: &str, typ: u32, len: u32, hash: u64, preview: &str) {
    out.push_str("V\t");
    escape_into(key, out);
    out.push('\t');
    escape_into(name, out);
    use std::fmt::Write;
    let _ = write!(out, "\t{typ}\t{len}\t{hash:016x}\t");
    escape_into(preview, out);
    out.push('\n');
}

/// First 16 hex chars of SHA-256 of the data, as u64.
pub fn data_hash(data: &[u8]) -> u64 {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(data);
    u64::from_be_bytes(d[..8].try_into().unwrap())
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

fn utf16(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

/// Preview per RIG.md §2, truncated to 1024 chars.
pub fn preview(typ: u32, data: &[u8]) -> String {
    let s = match typ {
        REG_SZ | REG_EXPAND_SZ => {
            let w = utf16(data);
            let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
            String::from_utf16_lossy(&w[..end])
        }
        REG_LINK => {
            let w = utf16(data);
            let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
            String::from_utf16_lossy(&w[..end])
        }
        REG_MULTI_SZ => {
            let w = utf16(data);
            let mut parts: Vec<String> = w.split(|&c| c == 0).map(String::from_utf16_lossy).collect();
            while parts.last().is_some_and(|p| p.is_empty()) {
                parts.pop();
            }
            parts.join("\0")
        }
        REG_DWORD if data.len() == 4 => u32::from_le_bytes(data.try_into().unwrap()).to_string(),
        REG_QWORD if data.len() == 8 => u64::from_le_bytes(data.try_into().unwrap()).to_string(),
        _ => String::new(),
    };
    truncate_chars(s, PREVIEW_MAX)
}

pub fn truncate_chars(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s,
    }
}

/// Find the snap file for a phase inside a run dir: `snap-<phase>.tsv.gz` or `snap-<run>-<phase>.tsv.gz`.
pub fn find_phase_file(dir: &Path, prefix: &str, phase: &str, ext: &str) -> Option<std::path::PathBuf> {
    let direct = dir.join(format!("{prefix}-{phase}{ext}"));
    if direct.is_file() {
        return Some(direct);
    }
    let suffix = format!("-{phase}{ext}");
    let mut hits: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
            n.starts_with(&format!("{prefix}-")) && n.ends_with(&suffix)
        })
        .collect();
    hits.sort();
    hits.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip() {
        let mut t = header_line(&Header {
            time: "2026-01-01T00:00:00Z".into(),
            computer: "PC".into(),
            edition: "EnterpriseS".into(),
            build: "26100.1".into(),
        });
        write_d(&mut t, "C:\\a\tb", 0x10, 5, 0);
        write_f(&mut t, "C:\\a\tb\\f\\n", 12, 0x20, 7, 0xa000_000c);
        write_k(&mut t, "HKLM\\SOFTWARE\\X", 9, Some(2), None);
        write_v(&mut t, "HKLM\\SOFTWARE\\X", "", REG_SZ, 4, 0xdead_beef, "hi\0there\\");
        write_v(&mut t, "HKLM\\SOFTWARE\\X", "Name\twith tab", REG_DWORD, 4, 1, "5");
        t.push_str(&meta_line("errors", &["2".into(), "C:\\x|C:\\y".into()]));
        let s = Snap::from_text(&t).unwrap();
        assert_eq!(s.header.edition, "EnterpriseS");
        assert!(s.path("c:\\A\tB").unwrap().dir);
        let f = s.path("C:\\a\tb\\f\\n").unwrap();
        assert_eq!((f.size, f.attrs, f.reparse), (12, 0x20, 0xa000_000c));
        let k = s.key("hklm\\software\\x").unwrap();
        assert_eq!((k.nv, k.ns), (Some(2), None));
        assert_eq!(s.value("HKLM\\SOFTWARE\\X", "").unwrap().preview, "hi\0there\\");
        assert_eq!(s.value("HKLM\\SOFTWARE\\X", "name\tWITH tab").unwrap().hash, 1);
        assert_eq!(s.errors, 2);
        assert_eq!(s.error_paths, vec!["C:\\x", "C:\\y"]);
    }

    #[test]
    fn sid_guess_and_capture_area() {
        let mut t = header_line(&Header::default());
        t.push_str(&meta_line(
            "roots",
            &["HKU\\S-1-5-21-1-2-3-1001".into(), "C:\\Users".into(), "C:\\Windows@1".into()],
        ));
        t.push_str(&meta_line("exclude", &["HKU\\S-1-5-21-1-2-3-1001\\Volatile".into()]));
        write_k(&mut t, "HKU\\S-1-5-18\\Software", 1, Some(0), Some(0));
        write_k(&mut t, "HKU\\S-1-5-21-1-2-3-1001\\Software", 1, Some(0), Some(0));
        write_d(&mut t, "C:\\Users\\All Users", 0x2410, 1, 0xa000_000c);
        let s = Snap::from_text(&t).unwrap();
        assert_eq!(s.guess_user_sid().as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert!(s.captures_key("HKU\\S-1-5-21-1-2-3-1001\\Software\\X"));
        assert!(!s.captures_key("HKU\\S-1-5-21-1-2-3-1001\\Volatile\\X"));
        assert!(!s.captures_key("HKLM\\SOFTWARE\\X"));
        assert!(s.captures_path("C:\\Users\\t\\AppData\\x.txt"));
        assert!(!s.captures_path("C:\\Users\\All Users\\x.txt")); // below a junction: never traversed
        assert!(s.captures_path("C:\\Windows\\notepad.exe"));
        assert!(!s.captures_path("C:\\Windows\\System32\\x.dll")); // depth-1 root
        assert!(!s.captures_path("C:\\UsersX\\a"));
    }

    #[test]
    fn denied_markers_and_links() {
        let mut t = header_line(&Header::default());
        t.push_str(&meta_line("roots", &["HKLM\\SOFTWARE".into(), "C:\\ProgramData".into(), "HKU\\S-1-5-18".into()]));
        write_k(&mut t, "HKLM\\SOFTWARE\\WOW6432Node\\Clients", 1, Some(1), Some(0));
        write_v(&mut t, "HKLM\\SOFTWARE\\WOW6432Node\\Clients", "SymbolicLinkValue", REG_LINK, 68, 1, "\\REGISTRY\\MACHINE\\SOFTWARE\\Clients");
        write_d(&mut t, "C:\\ProgramData\\Denied", 0x10, 1, 0);
        t.push_str(&meta_line("denied", &["C:\\ProgramData\\Denied".into()]));
        write_k(&mut t, "HKU\\S-1-5-18", 1, Some(1), Some(0));
        write_k(&mut t, "HKU\\S-1-5-18\\Software", 1, Some(0), Some(0));
        let s = Snap::from_text(&t).unwrap();
        assert!(s.is_denied("c:\\programdata\\DENIED"));
        assert!(!s.captures_path("C:\\ProgramData\\Denied\\x"));
        assert_eq!(s.reg_links(), vec![("HKLM\\SOFTWARE\\WOW6432Node\\Clients".to_string(), "HKLM\\SOFTWARE\\Clients".to_string())]);
        // the link key itself stays, a followed copy below it is dropped
        assert!(s.has_key("HKU\\S-1-5-18"));
        assert!(!s.has_key("HKU\\S-1-5-18\\Software"));
        assert_eq!(s.alias_dropped, 1);
        // the #roots entry is read under the canonical name
        assert!(s.roots.iter().any(|r| r.path == "HKU\\.DEFAULT"));
    }

    #[test]
    fn previews() {
        let sz: Vec<u8> = "ab\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(preview(REG_SZ, &sz), "ab");
        let m: Vec<u8> = "a\0b\0\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(preview(REG_MULTI_SZ, &m), "a\0b");
        assert_eq!(preview(REG_DWORD, &7u32.to_le_bytes()), "7");
        assert_eq!(preview(REG_QWORD, &(1u64 << 40).to_le_bytes()), (1u64 << 40).to_string());
        assert_eq!(preview(3, &[1, 2]), "");
        let long: Vec<u8> = "x".repeat(3000).encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(preview(REG_SZ, &long).len(), 1024);
        assert_eq!(format!("{:016x}", data_hash(b"")), "e3b0c44298fc1c14");
    }
}
