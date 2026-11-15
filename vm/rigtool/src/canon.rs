//! Canonicalisation of registry keys and file paths, plus case-insensitive identity helpers.
//!
//! Every comparison in rigtool goes through this module:
//! - registry roots: `HKEY_LOCAL_MACHINE`/`HKLM:` -> `HKLM`, `HKEY_CURRENT_USER`/`HKCU` -> `HKU\<sid>`
//!   (when a SID is known), `HKEY_CLASSES_ROOT`/`HKCR` -> `HKLM\SOFTWARE\Classes`, `HKEY_USERS` -> `HKU`,
//!   `HKLM\SYSTEM\ControlSet00N` -> `HKLM\SYSTEM\CurrentControlSet`;
//! - registry links (the capture records link keys and never follows them, so only the target
//!   spelling holds data): `HKU\<user sid>\Software\Classes` -> `HKU\<user sid>_Classes` (user hives only),
//!   `HKU\S-1-5-18` -> `HKU\.DEFAULT`, `HKLM\SOFTWARE\WOW6432Node\Classes` -> `HKLM\SOFTWARE\Classes\Wow6432Node`,
//!   `HKLM\SOFTWARE\WOW6432Node\{Clients,Policies,RegisteredApplications}` -> `HKLM\SOFTWARE\…`; any
//!   other link a snap recorded is resolved with [`LinkMap`];
//! - paths: no `\\?\` prefix, `/` -> `\`, no doubled separators, no trailing `\` (except `C:\`);
//! - identity is case-insensitive (Unicode simple lowercase), original case is kept for output;
//! - ancestry is separator-aware: `HKLM\SOFTWARE\Moz` is not an ancestor of `HKLM\SOFTWARE\Mozilla`.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

// ---------------------------------------------------------------------------------------------
// Case-insensitive strings
// ---------------------------------------------------------------------------------------------

/// Lowercase fold used for every identity comparison (per-char, context free).
pub fn fold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    s.chars().flat_map(char::to_lowercase).collect()
}

pub fn ci_hash(s: &str) -> u64 {
    const P: u64 = 0x0000_0100_0000_01b3;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    if s.is_ascii() {
        for b in s.bytes() {
            h ^= b.to_ascii_lowercase() as u64;
            h = h.wrapping_mul(P);
        }
    } else {
        for c in s.chars().flat_map(char::to_lowercase) {
            h ^= c as u64;
            h = h.wrapping_mul(P);
        }
    }
    h
}

pub fn ci_eq(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars().flat_map(char::to_lowercase).eq(b.chars().flat_map(char::to_lowercase))
}

pub fn ci_cmp(a: &str, b: &str) -> Ordering {
    if a.is_ascii() && b.is_ascii() {
        return a.bytes().map(|c| c.to_ascii_lowercase()).cmp(b.bytes().map(|c| c.to_ascii_lowercase()));
    }
    a.chars().flat_map(char::to_lowercase).cmp(b.chars().flat_map(char::to_lowercase))
}

/// Borrowed case-insensitive string (hash map lookup key).
#[repr(transparent)]
pub struct CiStr(str);

impl CiStr {
    pub fn new(s: &str) -> &CiStr {
        // SAFETY: CiStr is repr(transparent) over str.
        unsafe { &*(s as *const str as *const CiStr) }
    }
}
impl PartialEq for CiStr {
    fn eq(&self, o: &Self) -> bool {
        ci_eq(&self.0, &o.0)
    }
}
impl Eq for CiStr {}
impl Hash for CiStr {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write_u64(ci_hash(&self.0));
    }
}

/// Owned case-insensitive string that keeps its original case.
#[derive(Clone, Debug)]
pub struct CiString(pub String);

impl CiString {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl From<&str> for CiString {
    fn from(s: &str) -> Self {
        CiString(s.to_string())
    }
}
impl From<String> for CiString {
    fn from(s: String) -> Self {
        CiString(s)
    }
}
impl Borrow<CiStr> for CiString {
    fn borrow(&self) -> &CiStr {
        CiStr::new(&self.0)
    }
}
impl PartialEq for CiString {
    fn eq(&self, o: &Self) -> bool {
        ci_eq(&self.0, &o.0)
    }
}
impl Eq for CiString {}
impl Hash for CiString {
    fn hash<H: Hasher>(&self, h: &mut H) {
        h.write_u64(ci_hash(&self.0));
    }
}

// ---------------------------------------------------------------------------------------------
// Hierarchy
// ---------------------------------------------------------------------------------------------

/// Parent of a key or path. `C:\a` -> `C:\`, `C:\` -> None, `HKLM\SOFTWARE` -> `HKLM`, `HKLM` -> None.
pub fn parent(s: &str) -> Option<&str> {
    let t = s.strip_suffix('\\').unwrap_or(s);
    if is_drive_root(s) {
        return None;
    }
    let i = t.rfind('\\')?;
    if i == 0 {
        return None;
    }
    let p = &s[..i];
    if p.len() == 2 && p.as_bytes()[1] == b':' {
        return Some(&s[..i + 1]);
    }
    // UNC: never go above \\server
    if p == "\\" {
        return None;
    }
    Some(p)
}

/// Strict ancestors, nearest first.
pub fn ancestors(s: &str) -> Ancestors<'_> {
    Ancestors { cur: Some(s) }
}

pub struct Ancestors<'a> {
    cur: Option<&'a str>,
}
impl<'a> Iterator for Ancestors<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<&'a str> {
        let p = parent(self.cur?);
        self.cur = p;
        p
    }
}

fn is_drive_root(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() == 3 && b[1] == b':' && b[2] == b'\\') || (b.len() == 2 && b[1] == b':')
}

/// `child` equals `anc` or lies below it. Both must already be folded (see [`fold`]).
pub fn is_under_or_eq_folded(child: &str, anc: &str) -> bool {
    if !child.starts_with(anc) {
        return false;
    }
    if child.len() == anc.len() {
        return true;
    }
    anc.ends_with('\\') || child.as_bytes()[anc.len()] == b'\\'
}

/// Case-insensitive, separator-aware: `child` equals `anc` or lies below it.
pub fn is_under_or_eq(child: &str, anc: &str) -> bool {
    is_under_or_eq_folded(&fold(child), &fold(anc))
}

/// Strictly below.
pub fn is_strictly_under(child: &str, anc: &str) -> bool {
    let c = fold(child);
    let a = fold(anc);
    c.len() != a.len() && is_under_or_eq_folded(&c, &a)
}

/// Sorted index of folded paths supporting "all entries equal to or below X" range queries.
#[derive(Default)]
pub struct PrefixIndex<T> {
    v: Vec<(String, T)>,
}

impl<T: Clone> PrefixIndex<T> {
    pub fn new(mut v: Vec<(String, T)>) -> Self {
        for e in v.iter_mut() {
            e.0 = fold(&e.0);
        }
        v.sort_by(|a, b| a.0.cmp(&b.0));
        PrefixIndex { v }
    }
    /// Entries equal to `anc` or below it.
    pub fn under_or_eq(&self, anc: &str) -> Vec<T> {
        let a = fold(anc);
        let start = self.v.partition_point(|e| e.0.as_str() < a.as_str());
        let mut out = Vec::new();
        for e in &self.v[start..] {
            if !e.0.starts_with(&a) {
                break;
            }
            if is_under_or_eq_folded(&e.0, &a) {
                out.push(e.1.clone());
            }
        }
        out
    }
    /// Entries that are `p` itself or a strict ancestor of it.
    pub fn ancestors_or_eq(&self, p: &str) -> Vec<T> {
        let f = fold(p);
        let mut out = Vec::new();
        let mut cur: Option<&str> = Some(&f);
        while let Some(c) = cur {
            let start = self.v.partition_point(|e| e.0.as_str() < c);
            for e in &self.v[start..] {
                if e.0 != c {
                    break;
                }
                out.push(e.1.clone());
            }
            cur = parent(c);
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Canonical forms
// ---------------------------------------------------------------------------------------------

/// Does this string name a registry key (rather than a file path)?
pub fn looks_like_reg(s: &str) -> bool {
    let t = s.trim_start();
    let u = t.get(..t.len().min(48)).unwrap_or(t).to_ascii_uppercase();
    u.starts_with("HKEY_")
        || u.starts_with("HKLM")
        || u.starts_with("HKCU")
        || u.starts_with("HKCR")
        || u.starts_with("HKU\\")
        || u == "HKU"
        || u.starts_with("HKU:")
        || u.starts_with("HKCC")
        || u.starts_with("REGISTRY::")
        || u.starts_with("MICROSOFT.POWERSHELL.CORE\\REGISTRY::")
        || u.starts_with("\\REGISTRY\\")
        || u.starts_with("COMPUTER\\HK")
}

/// Canonical registry key. `sid` maps HKCU; without it HKCU stays `HKCU`.
pub fn canon_reg(s: &str, sid: Option<&str>) -> String {
    let mut t = s.trim();
    for pre in ["Microsoft.PowerShell.Core\\Registry::", "Registry::", "Computer\\"] {
        // `get`: the key may hold non-ASCII text, and a byte index inside a character would panic.
        if t.get(..pre.len()).is_some_and(|h| h.eq_ignore_ascii_case(pre)) {
            t = &t[pre.len()..];
        }
    }
    // Collapse doubled separators and drop trailing ones.
    let mut norm = String::with_capacity(t.len());
    let mut prev_sep = false;
    for c in t.chars() {
        if c == '\\' {
            if prev_sep {
                continue;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
        norm.push(c);
    }
    while norm.ends_with('\\') {
        norm.pop();
    }
    let mut segs: Vec<&str> = norm.split('\\').collect();
    // \REGISTRY\MACHINE\... and \REGISTRY\USER\...
    if segs.len() >= 3 && segs[0].is_empty() && segs[1].eq_ignore_ascii_case("REGISTRY") {
        let head = if segs[2].eq_ignore_ascii_case("MACHINE") {
            "HKLM"
        } else if segs[2].eq_ignore_ascii_case("USER") {
            "HKU"
        } else {
            segs[2]
        };
        let mut v = vec![head];
        v.extend_from_slice(&segs[3..]);
        segs = v;
    }
    if segs.is_empty() {
        return String::new();
    }
    let head = segs[0].trim_end_matches(':').to_ascii_uppercase();
    let sid_root;
    let mapped: &str = match head.as_str() {
        "HKEY_LOCAL_MACHINE" | "HKLM" => "HKLM",
        "HKEY_CURRENT_USER" | "HKCU" => match sid {
            Some(s) => {
                sid_root = format!("HKU\\{s}");
                &sid_root
            }
            None => "HKCU",
        },
        "HKEY_CLASSES_ROOT" | "HKCR" => "HKLM\\SOFTWARE\\Classes",
        "HKEY_USERS" | "HKU" => "HKU",
        "HKEY_CURRENT_CONFIG" | "HKCC" => "HKLM\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current",
        _ => segs[0],
    };
    let mut out: Vec<String> = mapped.split('\\').map(str::to_string).collect();
    out.extend(segs[1..].iter().map(|s| s.to_string()));
    // HKU\S-1-5-18 is a registry link to HKU\.DEFAULT (the capture records the link, never follows it).
    if out.len() >= 2
        && out[0] == "HKU"
        && (out[1].eq_ignore_ascii_case("S-1-5-18") || out[1].eq_ignore_ascii_case(".DEFAULT"))
    {
        out[1] = ".DEFAULT".to_string();
    }
    // HKU\<user sid>\Software\Classes -> HKU\<user sid>_Classes (a link to the classes hive). Only user
    // hives have a `_Classes` hive; HKU\.DEFAULT\Software\Classes is an ordinary key.
    if out.len() >= 4
        && out[0] == "HKU"
        && is_user_sid(&out[1], sid)
        && out[2].eq_ignore_ascii_case("Software")
        && out[3].eq_ignore_ascii_case("Classes")
    {
        let sidc = format!("{}_Classes", out[1]);
        let mut v = vec!["HKU".to_string(), sidc];
        v.extend(out.drain(4..));
        out = v;
    }
    // HKLM\SYSTEM\ControlSet00N -> CurrentControlSet
    if out.len() >= 3
        && out[0] == "HKLM"
        && out[1].eq_ignore_ascii_case("SYSTEM")
        && out[2].len() == 13
        && out[2][..10].eq_ignore_ascii_case("ControlSet")
        && out[2][10..].bytes().all(|b| b.is_ascii_digit())
    {
        out[2] = "CurrentControlSet".to_string();
    }
    if out.len() >= 2 && out[0] == "HKLM" && out[1].eq_ignore_ascii_case("SOFTWARE") {
        out[1] = "SOFTWARE".to_string();
    }
    if out.len() >= 2 && out[0] == "HKLM" && out[1].eq_ignore_ascii_case("SYSTEM") {
        out[1] = "SYSTEM".to_string();
    }
    // Registry links of the 32-bit SOFTWARE view (recorded as link keys by the capture, never followed):
    //   HKLM\SOFTWARE\WOW6432Node\Classes -> HKLM\SOFTWARE\Classes\Wow6432Node
    //   HKLM\SOFTWARE\WOW6432Node\{Clients,Policies,RegisteredApplications} -> HKLM\SOFTWARE\<same>
    if out.len() >= 4 && out[0] == "HKLM" && out[1] == "SOFTWARE" && out[2].eq_ignore_ascii_case("WOW6432Node") {
        let l = out[3].to_ascii_lowercase();
        match l.as_str() {
            "classes" => {
                out[2] = "Classes".to_string();
                out[3] = "Wow6432Node".to_string();
            }
            "clients" | "policies" | "registeredapplications" => {
                out.remove(2);
            }
            _ => {}
        }
    }
    out.join("\\")
}

/// A `HKU\<x>` hive name that has a `_Classes` companion: interactive users (`S-1-5-21-…`, Azure AD
/// `S-1-12-1-…`) and the run's own SID. Never `.DEFAULT`, the service SIDs or a `_Classes` hive itself.
fn is_user_sid(x: &str, sid: Option<&str>) -> bool {
    let u = x.to_ascii_uppercase();
    if u.ends_with("_CLASSES") {
        return false;
    }
    u.starts_with("S-1-5-21-") || u.starts_with("S-1-12-1-") || sid.is_some_and(|s| s.eq_ignore_ascii_case(x))
}

/// Registry symbolic links seen in a capture (link key -> canonical target), applied by longest prefix.
/// `canon_reg` already folds the well-known Windows links; this covers any other link a snap recorded.
#[derive(Default, Clone, Debug)]
pub struct LinkMap {
    /// (folded link key, segment count, canonical target), longest first.
    v: Vec<(String, usize, String)>,
}

impl LinkMap {
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> LinkMap {
        let mut v: Vec<(String, usize, String)> = pairs
            .into_iter()
            .filter_map(|(src, dst)| {
                let f = fold(&src);
                let fd = fold(&dst);
                // A link onto itself or below itself would never terminate.
                if f.is_empty() || fd.is_empty() || is_under_or_eq_folded(&fd, &f) {
                    return None;
                }
                let n = f.split('\\').count();
                Some((f, n, dst))
            })
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.dedup_by(|a, b| a.0 == b.0);
        LinkMap { v }
    }

    /// Rewrite a canonical key that lies under a link key to the link's target (repeatedly, max 8 hops).
    pub fn resolve(&self, key: &str) -> String {
        let mut cur = key.to_string();
        for _ in 0..8 {
            let f = fold(&cur);
            let Some((_, n, dst)) = self.v.iter().find(|(s, _, _)| is_under_or_eq_folded(&f, s)) else {
                break;
            };
            let mut next = dst.clone();
            for seg in cur.split('\\').skip(*n) {
                next.push('\\');
                next.push_str(seg);
            }
            cur = next;
        }
        cur
    }
}

/// Canonical file path.
pub fn canon_path(s: &str) -> String {
    let mut t = s.trim().replace('/', "\\");
    if let Some(r) = t.strip_prefix("\\\\?\\UNC\\") {
        t = format!("\\\\{r}");
    } else if let Some(r) = t.strip_prefix("\\\\?\\") {
        t = r.to_string();
    } else if let Some(r) = t.strip_prefix("\\??\\") {
        t = r.to_string();
    }
    let unc = t.starts_with("\\\\");
    let mut out = String::with_capacity(t.len());
    if unc {
        out.push_str("\\\\");
    }
    let body = if unc { &t[2..] } else { &t[..] };
    let mut prev_sep = false;
    for c in body.chars() {
        if c == '\\' {
            if prev_sep {
                continue;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
        out.push(c);
    }
    while out.ends_with('\\') && !is_drive_root(&out) && out.len() > 2 {
        out.pop();
    }
    if out.len() == 2 && out.as_bytes()[1] == b':' {
        out.push('\\');
    }
    // Upper-case drive letter, as Windows reports it.
    if out.len() >= 2 && out.as_bytes()[1] == b':' && out.as_bytes()[0].is_ascii_lowercase() {
        let d = out.as_bytes()[0].to_ascii_uppercase() as char;
        out.replace_range(0..1, &d.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn reg_roots() {
        assert_eq!(canon_reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Mozilla\\", None), "HKLM\\SOFTWARE\\Mozilla");
        assert_eq!(canon_reg("HKLM:\\Software\\X", None), "HKLM\\SOFTWARE\\X");
        assert_eq!(
            canon_reg("HKEY_CURRENT_USER\\Software\\Mozilla", Some(SID)),
            format!("HKU\\{SID}\\Software\\Mozilla")
        );
        assert_eq!(canon_reg("HKCU\\Software\\Mozilla", Some(SID)), format!("HKU\\{SID}\\Software\\Mozilla"));
        assert_eq!(canon_reg("HKCU\\Software\\Mozilla", None), "HKCU\\Software\\Mozilla");
        assert_eq!(canon_reg("HKEY_CLASSES_ROOT\\.txt", None), "HKLM\\SOFTWARE\\Classes\\.txt");
        assert_eq!(canon_reg("HKCR\\CLSID\\{X}", None), "HKLM\\SOFTWARE\\Classes\\CLSID\\{X}");
        assert_eq!(canon_reg("HKEY_USERS\\.DEFAULT\\Software", None), "HKU\\.DEFAULT\\Software");
        assert_eq!(canon_reg("Registry::HKEY_USERS\\S-1\\X", None), "HKU\\S-1\\X");
        assert_eq!(canon_reg("\\REGISTRY\\MACHINE\\SOFTWARE\\A", None), "HKLM\\SOFTWARE\\A");
        assert_eq!(
            canon_reg("HKLM\\SYSTEM\\ControlSet001\\Services\\X", None),
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\X"
        );
        assert_eq!(canon_reg("HKLM\\\\SOFTWARE\\\\A\\\\", None), "HKLM\\SOFTWARE\\A");
    }

    #[test]
    fn hkcu_classes_maps_to_classes_hive() {
        assert_eq!(
            canon_reg("HKEY_CURRENT_USER\\Software\\Classes\\FirefoxPDF-1", Some(SID)),
            format!("HKU\\{SID}_Classes\\FirefoxPDF-1")
        );
        assert_eq!(canon_reg(&format!("HKU\\{SID}\\Software\\Classes"), None), format!("HKU\\{SID}_Classes"));
        // already the classes hive: unchanged
        assert_eq!(canon_reg(&format!("HKU\\{SID}_Classes\\x"), None), format!("HKU\\{SID}_Classes\\x"));
        // the run's SID, whatever its shape
        assert_eq!(canon_reg("HKU\\S-1-9-9\\Software\\Classes\\x", Some("S-1-9-9")), "HKU\\S-1-9-9_Classes\\x");
    }

    #[test]
    fn default_hive_classes_is_a_real_key() {
        // HKU\.DEFAULT\Software\Classes is an ordinary key: no `_Classes` rewrite.
        assert_eq!(
            canon_reg("HKU\\.DEFAULT\\Software\\Classes\\Foo", Some(SID)),
            "HKU\\.DEFAULT\\Software\\Classes\\Foo"
        );
        assert_eq!(canon_reg("HKEY_USERS\\.default\\Software\\Classes", None), "HKU\\.DEFAULT\\Software\\Classes");
        // S-1-5-18 is a link to .DEFAULT
        assert_eq!(
            canon_reg("HKEY_USERS\\S-1-5-18\\Software\\Classes\\Foo", Some(SID)),
            "HKU\\.DEFAULT\\Software\\Classes\\Foo"
        );
        assert_eq!(canon_reg("HKU\\S-1-5-18", None), "HKU\\.DEFAULT");
        // service hives have no _Classes hive
        assert_eq!(canon_reg("HKU\\S-1-5-19\\Software\\Classes\\X", Some(SID)), "HKU\\S-1-5-19\\Software\\Classes\\X");
        assert_eq!(canon_reg("HKU\\S-1-5-20\\Software\\Classes", None), "HKU\\S-1-5-20\\Software\\Classes");
    }

    #[test]
    fn wow64_link_aliases() {
        // Entries from the old UT data (firefox-ut-removed.json, 7zip-bcu-removed.json).
        assert_eq!(
            canon_reg(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Classes\\AppID\\{56932DBC-A2C3-452E-B42D-7FD6CCAC6FCE}",
                None
            ),
            "HKLM\\SOFTWARE\\Classes\\Wow6432Node\\AppID\\{56932DBC-A2C3-452E-B42D-7FD6CCAC6FCE}"
        );
        assert_eq!(
            canon_reg(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet\\Firefox-308046B0AF4A39CB",
                None
            ),
            "HKLM\\SOFTWARE\\Clients\\StartMenuInternet\\Firefox-308046B0AF4A39CB"
        );
        assert_eq!(
            canon_reg(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Classes\\CLSID\\{23170F69-40C1-278A-1000-000100020000}",
                None
            ),
            "HKLM\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{23170F69-40C1-278A-1000-000100020000}"
        );
        assert_eq!(canon_reg("hklm\\software\\wow6432node\\policies\\x", None), "HKLM\\SOFTWARE\\policies\\x");
        assert_eq!(
            canon_reg("HKLM\\SOFTWARE\\WOW6432Node\\RegisteredApplications", None),
            "HKLM\\SOFTWARE\\RegisteredApplications"
        );
        // the link keys' parent and other WOW6432Node keys are real keys
        assert_eq!(canon_reg("HKLM\\SOFTWARE\\WOW6432Node", None), "HKLM\\SOFTWARE\\WOW6432Node");
        assert_eq!(canon_reg("HKLM\\SOFTWARE\\WOW6432Node\\Mozilla", None), "HKLM\\SOFTWARE\\WOW6432Node\\Mozilla");
        assert_eq!(canon_reg("HKLM\\SOFTWARE\\WOW6432Node\\ClientsX", None), "HKLM\\SOFTWARE\\WOW6432Node\\ClientsX");
    }

    #[test]
    fn link_map() {
        let m = LinkMap::new(vec![
            ("HKLM\\SOFTWARE\\Odd\\Link".to_string(), "HKLM\\SOFTWARE\\Real".to_string()),
            ("HKLM\\SOFTWARE\\Odd".to_string(), "HKLM\\SOFTWARE\\Other".to_string()),
            ("HKLM\\SOFTWARE\\Loop".to_string(), "HKLM\\SOFTWARE\\Loop\\x".to_string()),
        ]);
        assert_eq!(m.v.len(), 2);
        // longest link wins
        assert_eq!(m.resolve("hklm\\software\\odd\\LINK\\a\\b"), "HKLM\\SOFTWARE\\Real\\a\\b");
        assert_eq!(m.resolve("HKLM\\SOFTWARE\\Odd\\Other"), "HKLM\\SOFTWARE\\Other\\Other");
        assert_eq!(m.resolve("HKLM\\SOFTWARE\\Oddity"), "HKLM\\SOFTWARE\\Oddity");
        assert_eq!(m.resolve("HKLM\\SOFTWARE\\Loop\\x"), "HKLM\\SOFTWARE\\Loop\\x");
    }

    #[test]
    fn paths() {
        assert_eq!(canon_path("\\\\?\\C:\\Program Files\\X\\"), "C:\\Program Files\\X");
        assert_eq!(canon_path("c:/users//x/"), "C:\\users\\x");
        assert_eq!(canon_path("C:\\"), "C:\\");
        assert_eq!(canon_path("C:"), "C:\\");
        assert_eq!(canon_path("\\\\?\\UNC\\srv\\share\\a"), "\\\\srv\\share\\a");
    }

    #[test]
    fn separator_aware_ancestry() {
        assert!(!is_under_or_eq("HKLM\\SOFTWARE\\Mozilla", "HKLM\\SOFTWARE\\Moz"));
        assert!(is_under_or_eq("HKLM\\SOFTWARE\\Mozilla\\Firefox", "hklm\\software\\mozilla"));
        assert!(is_under_or_eq("HKLM\\SOFTWARE\\Mozilla", "HKLM\\SOFTWARE\\MOZILLA"));
        assert!(!is_strictly_under("HKLM\\SOFTWARE\\Mozilla", "HKLM\\SOFTWARE\\MOZILLA"));
        assert!(is_under_or_eq("C:\\Program Files\\A", "C:\\"));
        assert!(!is_under_or_eq("C:\\Program Files (x86)\\A", "C:\\Program Files"));
        assert!(!is_under_or_eq("D:\\x", "C:\\"));
    }

    #[test]
    fn parents_and_ancestors() {
        assert_eq!(parent("C:\\a\\b"), Some("C:\\a"));
        assert_eq!(parent("C:\\a"), Some("C:\\"));
        assert_eq!(parent("C:\\"), None);
        assert_eq!(parent("HKLM\\SOFTWARE"), Some("HKLM"));
        assert_eq!(parent("HKLM"), None);
        let a: Vec<&str> = ancestors("HKLM\\SOFTWARE\\A\\B").collect();
        assert_eq!(a, vec!["HKLM\\SOFTWARE\\A", "HKLM\\SOFTWARE", "HKLM"]);
    }

    #[test]
    fn ci_map_and_prefix_index() {
        let mut m: HashMap<CiString, u32> = HashMap::new();
        m.insert(CiString::from("HKLM\\SOFTWARE\\Mozilla"), 1);
        assert_eq!(m.get(CiStr::new("hklm\\software\\MOZILLA")), Some(&1));
        assert_eq!(m.get(CiStr::new("hklm\\software\\MOZ")), None);
        m.insert(CiString::from("C:\\\u{00c9}t\u{00e9}"), 2);
        assert_eq!(m.get(CiStr::new("c:\\\u{00e9}T\u{00c9}")), Some(&2));

        let idx = PrefixIndex::new(vec![
            ("HKLM\\SOFTWARE\\Moz".to_string(), 0),
            ("HKLM\\SOFTWARE\\Mozilla".to_string(), 1),
            ("HKLM\\SOFTWARE\\Mozilla\\Firefox".to_string(), 2),
            ("HKLM\\SOFTWARE\\Mozilla Foundation".to_string(), 3),
        ]);
        let mut u = idx.under_or_eq("hklm\\software\\mozilla");
        u.sort();
        assert_eq!(u, vec![1, 2]);
        let mut a = idx.ancestors_or_eq("HKLM\\SOFTWARE\\Mozilla\\Firefox\\x");
        a.sort();
        assert_eq!(a, vec![1, 2]);
        assert!(idx.ancestors_or_eq("HKLM\\SOFTWARE\\Mozillax").is_empty());
    }
}
