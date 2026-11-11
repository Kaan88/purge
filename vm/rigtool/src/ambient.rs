//! Ambient set (RIG.md §6): Windows churn seen in null runs, exact and generalized.

use crate::canon::{self};
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

/// Generalize a canonical target string: GUIDs, hex runs of 16+ and numbers of 6+ digits become
/// typed wildcards. Returns an anchored regex (case-insensitive use), or None if nothing was random.
/// Path/key patterns also match descendants; value patterns match `V:` and `C:` alike.
pub fn generalize(cs: &str) -> Option<String> {
    let (kind, body) = cs.split_once(':')?;
    let re = token_re();
    let mut out = String::new();
    let mut last = 0;
    let mut n = 0;
    for c in re.captures_iter(body) {
        let m = c.get(0).unwrap();
        out.push_str(&regex::escape(&body[last..m.start()]));
        out.push_str(if c.name("guid").is_some() {
            W_GUID
        } else if c.name("hex").is_some() {
            W_HEX
        } else {
            W_NUM
        });
        last = m.end();
        n += 1;
    }
    if n == 0 {
        return None;
    }
    out.push_str(&regex::escape(&body[last..]));
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
}

impl AmbientSet {
    pub fn load(path: &Path) -> Result<AmbientSet> {
        let j: AmbientJson = jsonio::read(path)?;
        let union = Matcher::new("union", &j.exact, &j.patterns)?;
        let runs = j.runs.iter().map(|r| Matcher::new(&r.id, &r.exact, &r.patterns)).collect::<Result<Vec<_>>>()?;
        Ok(AmbientSet { union, runs })
    }
}

/// Canonical strings of the churn in one null run (rig items dropped).
pub fn run_items(s0: &Snap, s2: &Snap) -> Vec<String> {
    let rig = RigRules::new(&[s0, s2]);
    items::derive(s0, s2)
        .into_iter()
        .map(|i| i.target.canon_string())
        .filter(|cs| rig.check(cs).is_none())
        .collect()
}

pub fn build_run(id: &str, dir: &str, cs: Vec<String>) -> AmbientRunJson {
    let pats: BTreeSet<String> = cs.iter().filter_map(|c| generalize(c)).collect();
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
    let mut runs = Vec::new();
    for d in dirs {
        let f0 = snap::find_phase_file(d, "snap", "0", ".tsv.gz").with_context(|| format!("no snap-0 in {}", d.display()))?;
        let f2 = snap::find_phase_file(d, "snap", "2", ".tsv.gz").with_context(|| format!("no snap-2 in {}", d.display()))?;
        let s0 = Snap::load(&f0, LoadOpts::default())?;
        let s2 = Snap::load(&f2, LoadOpts::default())?;
        let cs = run_items(&s0, &s2);
        let id = d.file_name().and_then(|n| n.to_str()).unwrap_or("null").to_string();
        let r = build_run(&id, &d.display().to_string(), cs);
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
        let g = generalize("P:C:\\Users\\t\\AppData\\Local\\Temp\\{0A1B2C3D-0000-1111-2222-333344445555}").unwrap();
        let m = Matcher::new("x", &[], &[g]).unwrap();
        let t = |p: &str| Target::Path { path: p.into() };
        assert!(m.matches(&t("C:\\Users\\t\\AppData\\Local\\Temp\\{99999999-AAAA-bbbb-2222-333344445555}")).is_some());
        assert!(m.matches(&t("C:\\Users\\t\\AppData\\Local\\Temp\\{99999999-AAAA-bbbb-2222-333344445555}\\x.tmp")).is_some());
        assert!(m.matches(&t("C:\\Users\\t\\AppData\\Local\\Temp\\notaguid")).is_none());

        let h = generalize("K:HKLM\\SOFTWARE\\X\\cache-0123456789abcdef01").unwrap();
        let m = Matcher::new("x", &[], &[h]).unwrap();
        assert!(m.matches(&Target::RegKey { path: "HKLM\\SOFTWARE\\X\\cache-FEDCBA98765432100A".into() }).is_some());
        assert!(m.matches(&Target::RegKey { path: "HKLM\\SOFTWARE\\X\\cache-FEDCBA9876".into() }).is_none());

        let n = generalize("V:HKU\\S\\Software\\Y|LastRun_20261111").unwrap();
        let m = Matcher::new("x", &[], &[n]).unwrap();
        assert!(m.matches(&Target::RegValue { path: "HKU\\S\\Software\\Y".into(), name: "LastRun_20270101".into() }).is_some());
        assert!(
            m.matches(&Target::RegValueChanged {
                path: "HKU\\S\\Software\\Y".into(),
                name: "LastRun_20270101".into(),
                before: String::new(),
                after: String::new()
            })
            .is_some()
        );
        assert!(m.matches(&Target::RegValue { path: "HKU\\S\\Software\\Y".into(), name: "LastRun_2027".into() }).is_none());
        assert!(generalize("P:C:\\Program Files\\App\\app.exe").is_none());
    }

    #[test]
    fn exact_and_descendants() {
        let m = Matcher::new(
            "n1",
            &["P:C:\\Windows\\Prefetch\\X.pf".into(), "K:HKLM\\SOFTWARE\\Churn".into(), "C:HKLM\\SOFTWARE\\A|Counter".into()],
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
