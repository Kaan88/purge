//! `rigtool convert` (RIG.md §7 "Old tools"): old result files -> plan JSON.
//!
//! - clone `*-clone-uninstall.json`: `leftovers[].path`; preselected if `checked` (band Safe), otherwise
//!   listed but not preselected (band Likely).
//! - UT / BCU `*-removed.json`: a JSON array of strings; everything was removed, so every item is
//!   offered, preselected, band Safe.
//!
//! Strings starting with `HKEY_` / `HK` become `RegKey`, others `Path`. Paths are kept as written
//! (the scorer canonicalises); only a trailing backslash is dropped.

use crate::canon;
use crate::err::{Context, Result, bail};
use crate::jsonio;
use crate::score::{Plan, PlanItem};
use crate::target::Target;
use serde_json::Value;
use std::path::Path;

pub fn target_of(s: &str) -> Target {
    let mut t = s.trim().to_string();
    while t.ends_with('\\') && t.len() > 3 {
        t.pop();
    }
    if canon::looks_like_reg(&t) { Target::RegKey { path: t } } else { Target::Path { path: t } }
}

pub fn from_clone(v: &Value, app: &str) -> Result<Plan> {
    let left = v.get("leftovers").and_then(|x| x.as_array()).context("clone file: no leftovers[] array")?;
    let mut items = Vec::new();
    for l in left {
        let Some(p) = l.get("path").and_then(|x| x.as_str()) else { continue };
        let checked = l.get("checked").and_then(|x| x.as_bool()).unwrap_or(false);
        items.push(PlanItem {
            target: target_of(p),
            band: if checked { "Safe".into() } else { "Likely".into() },
            preselected: checked,
            scanner: Some("clone".into()),
            category: l.get("kind").and_then(|x| x.as_str()).map(str::to_string),
        });
    }
    Ok(Plan { schema: "purge.plan/0".into(), app: app.into(), tool: "clone".into(), mode: "post".into(), items })
}

pub fn from_removed(v: &Value, tool: &str, app: &str) -> Result<Plan> {
    let arr = match v {
        Value::Array(a) => a,
        _ => bail!("removed file: expected a JSON array of strings"),
    };
    let items = arr
        .iter()
        .filter_map(|x| x.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| PlanItem {
            target: target_of(s),
            band: "Safe".into(),
            preselected: true,
            scanner: Some(tool.to_string()),
            category: None,
        })
        .collect();
    Ok(Plan { schema: "purge.plan/0".into(), app: app.into(), tool: tool.into(), mode: "post".into(), items })
}

pub fn cmd_convert(clone: Option<&Path>, removed: Option<&Path>, tool: Option<&str>, app: &str, out: &Path) -> Result<()> {
    let plan = match (clone, removed) {
        (Some(c), None) => from_clone(&jsonio::read(c)?, app)?,
        (None, Some(r)) => {
            let tool = tool.context("--removed needs --tool ut|bcu")?;
            if !matches!(tool, "ut" | "bcu") {
                bail!("--tool must be ut or bcu");
            }
            from_removed(&jsonio::read(r)?, tool, app)?
        }
        _ => bail!("give exactly one of --clone FILE or --removed FILE"),
    };
    eprintln!("convert: {} items -> {}", plan.items.len(), out.display());
    jsonio::write(out, &plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes() {
        let c = json!({"leftovers":[
            {"checked":true,"kind":"File","path":"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Notepad.lnk","size":1175},
            {"checked":false,"kind":"Key(Lm)","path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Notepad++\\","size":0}]});
        let p = from_clone(&c, "npp").unwrap();
        assert_eq!(p.items.len(), 2);
        assert_eq!(
            p.items[0].target,
            Target::Path { path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Notepad.lnk".into() }
        );
        assert!(p.items[0].preselected);
        assert_eq!(p.items[1].target, Target::RegKey { path: "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Notepad++".into() });
        assert_eq!((p.items[1].band.as_str(), p.items[1].preselected), ("Likely", false));

        let r = json!(["C:\\Program Files\\Mozilla Firefox", "HKEY_CURRENT_USER\\Software\\Mozilla\\Firefox"]);
        let p = from_removed(&r, "bcu", "firefox").unwrap();
        assert_eq!(p.tool, "bcu");
        assert!(p.items.iter().all(|i| i.preselected && i.band == "Safe"));
        assert_eq!(p.items[1].target.kind(), "RegKey");
    }
}
