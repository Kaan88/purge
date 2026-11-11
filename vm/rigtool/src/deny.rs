//! Deny examples (`vm\truth\deny.json`): offered items that are always danger.
//!
//! Accepted shapes: a top-level array, or an object with one of `deny`, `rules`, `examples`, `items`.
//! Each entry is either a string (case-insensitive regex on the canonical target string, e.g.
//! `Notepad\.lnk$`), or an object with `match` / `regex` / `pattern` (regex), or `target` (a Target:
//! an offered item equal to or containing it is danger), plus an optional `why`.

use crate::canon;
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::target::Target;
use regex::{Regex, RegexBuilder};
use serde_json::Value;
use std::path::Path;

enum Rule {
    Re(Regex, String),
    Target(Target, String),
}

#[derive(Default)]
pub struct Deny {
    rules: Vec<Rule>,
}

impl Deny {
    pub fn load(path: &Path, sid: Option<&str>) -> Result<Deny> {
        let v: Value = jsonio::read(path)?;
        Deny::from_value(&v, sid)
    }

    pub fn from_value(v: &Value, sid: Option<&str>) -> Result<Deny> {
        let list = match v {
            Value::Array(a) => a.clone(),
            Value::Object(o) => ["deny", "rules", "examples", "items"]
                .iter()
                .find_map(|k| o.get(*k).and_then(|x| x.as_array()).cloned())
                .unwrap_or_default(),
            _ => bail!("deny.json: expected an array or an object"),
        };
        let mut rules = Vec::new();
        for e in list {
            let ci = |s: &str| RegexBuilder::new(s).case_insensitive(true).build().with_context(|| format!("deny regex {s:?}"));
            match &e {
                Value::String(s) => rules.push(Rule::Re(ci(s)?, s.clone())),
                Value::Object(o) => {
                    let why = o.get("why").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    if let Some(s) = ["match", "regex", "pattern"].iter().find_map(|k| o.get(*k).and_then(|x| x.as_str())) {
                        let w = if why.is_empty() { s.to_string() } else { why };
                        rules.push(Rule::Re(ci(s)?, w));
                    } else if let Some(t) = o.get("target") {
                        let t: Target = serde_json::from_value(t.clone()).context("deny target")?;
                        let t = t.canonical(sid);
                        let w = if why.is_empty() { t.canon_string() } else { why };
                        rules.push(Rule::Target(t, w));
                    }
                }
                _ => {}
            }
        }
        Ok(Deny { rules })
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Why `t` (canonical) is denied, if it is.
    pub fn check(&self, t: &Target) -> Option<String> {
        let cs = t.canon_string();
        for r in &self.rules {
            match r {
                Rule::Re(re, why) => {
                    if re.is_match(&cs) {
                        return Some(format!("deny: {why}"));
                    }
                }
                Rule::Target(d, why) => {
                    let same_kind_tree = matches!(
                        (t, d),
                        (Target::Path { .. }, Target::Path { .. }) | (Target::RegKey { .. }, Target::RegKey { .. })
                            | (Target::RegKey { .. }, Target::RegValue { .. })
                    );
                    let hit = if same_kind_tree {
                        canon::is_under_or_eq(d.path(), t.path())
                    } else {
                        canon::ci_eq(&d.canon_string(), &cs)
                    };
                    if hit {
                        return Some(format!("deny: {why}"));
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        let v = serde_json::json!({"deny": [
            r"Notepad\.lnk$",
            {"match": r"^K:HKLM\\SOFTWARE\\Classes\\\.txt$", "why": "txt"},
            {"target": {"type": "Path", "path": r"C:\Windows\System32"}}
        ]});
        let d = Deny::from_value(&v, None).unwrap();
        assert_eq!(d.len(), 3);
        let p = |s: &str| Target::Path { path: s.into() };
        assert!(d.check(&p(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk")).is_some());
        assert!(d.check(&p(r"C:\Program Files\Notepad++\x.lnk")).is_none());
        assert!(d.check(&Target::RegKey { path: r"HKLM\SOFTWARE\Classes\.txt".into() }).is_some());
        assert!(d.check(&Target::RegKey { path: r"HKLM\SOFTWARE\Classes\.txtfile".into() }).is_none());
        assert!(d.check(&p(r"C:\Windows")).is_some()); // contains a denied path
        assert!(d.check(&p(r"C:\Windows\System32\x.dll")).is_none()); // inside it: not by this rule
    }
}
