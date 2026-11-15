//! Change items between two snaps (RIG.md §5 item kinds) and the built-in rig exclusions (§1).

use crate::canon::{self, CiStr, CiString};
use crate::snap::Snap;
use crate::target::{TASKCACHE, Target};
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Item {
    pub target: Target,
    pub size: Option<u64>,
    pub lwt: Option<u64>,
    pub dir: Option<bool>,
}

fn preview_or_hash(v: &crate::snap::ValRec) -> String {
    if v.preview.is_empty() { format!("#{:016x}", v.hash) } else { v.preview.clone() }
}

/// Items present in `s2` and absent in `s0` (top-most for paths and keys), values added to keys that
/// existed in `s0`, and values whose data changed.
pub fn derive(s0: &Snap, s2: &Snap) -> Vec<Item> {
    let mut out = Vec::new();

    // --- paths ---
    let is_new_path = |p: &str| s2.has_path(p) && !s0.has_path(p);
    let mut sizes: HashMap<CiString, u64> = HashMap::new();
    let mut tops: Vec<(&str, &crate::snap::FsRec)> = Vec::new();
    for (p, r) in &s2.fs {
        if s0.has_path(p.as_str()) {
            continue;
        }
        // highest new ancestor (new-ness is contiguous from p upwards)
        let mut top = p.as_str();
        for a in canon::ancestors(p.as_str()) {
            if is_new_path(a) {
                top = a;
            } else {
                break;
            }
        }
        if !r.dir {
            *sizes.entry(CiString(top.to_string())).or_default() += r.size;
        }
        if std::ptr::eq(top, p.as_str()) {
            tops.push((p.as_str(), r));
        }
    }
    for (p, r) in tops {
        out.push(Item {
            target: Target::Path { path: p.to_string() },
            size: Some(sizes.get(CiStr::new(p)).copied().unwrap_or(0)),
            lwt: Some(r.mtime),
            dir: Some(r.dir),
        });
    }

    // --- keys ---
    let is_new_key = |k: &str| s2.has_key(k) && !s0.has_key(k);
    for (k, r) in &s2.keys {
        if !r.seen || s0.has_key(k.as_str()) {
            continue;
        }
        if canon::ancestors(k.as_str()).any(is_new_key) {
            continue;
        }
        out.push(Item { target: Target::RegKey { path: k.0.clone() }, size: None, lwt: Some(r.lwt), dir: None });
    }

    // --- values on keys that existed in s0 ---
    let values_comparable = s0.n_values > 0 && s2.n_values > 0;
    if values_comparable {
        for (k, r2) in &s2.keys {
            if !r2.seen || r2.nv.is_none() {
                continue;
            }
            let Some(r0) = s0.key(k.as_str()) else {
                continue;
            };
            if r0.nv.is_none() {
                continue; // s0 could not read this key: values unknown
            }
            for v in &r2.values {
                match r0.value(&v.name) {
                    None => out.push(Item {
                        target: Target::RegValue { path: k.0.clone(), name: v.name.clone() },
                        size: Some(v.len as u64),
                        lwt: Some(r2.lwt),
                        dir: None,
                    }),
                    Some(v0) if v0.hash != v.hash || v0.typ != v.typ => out.push(Item {
                        target: Target::RegValueChanged {
                            path: k.0.clone(),
                            name: v.name.clone(),
                            before: preview_or_hash(v0),
                            after: preview_or_hash(v),
                        },
                        size: Some(v.len as u64),
                        lwt: Some(r2.lwt),
                        dir: None,
                    }),
                    _ => {}
                }
            }
        }
    }
    sort_items(&mut out);
    out
}

pub fn sort_items(v: &mut [Item]) {
    v.sort_by(|a, b| {
        a.target
            .rank()
            .cmp(&b.target.rank())
            .then_with(|| canon::ci_cmp(a.target.path(), b.target.path()))
            .then_with(|| canon::ci_cmp(a.target.value_name().unwrap_or(""), b.target.value_name().unwrap_or("")))
    });
}

// ---------------------------------------------------------------------------------------------
// Rig exclusions (RIG.md §1)
// ---------------------------------------------------------------------------------------------

const RIG_TASKS: &str =
    r"PurgeRigAgent|PurgeRigLaunch|PurgeRigInstall|agentstart|elev[^\\|]*|crshot[^\\|]*|utrun|PurgeSetup";

pub struct RigRules {
    rules: Vec<(Regex, String)>,
}

fn ci(re: &str) -> Regex {
    RegexBuilder::new(re).case_insensitive(true).build().expect("rig regex")
}

impl RigRules {
    /// Build the rules; the snaps supply the TaskCache GUIDs of the rig's own tasks.
    pub fn new(snaps: &[&Snap]) -> RigRules {
        let tc = regex::escape(TASKCACHE);
        let mut rules = vec![
            (ci(r"^P:[A-Z]:\\(cr|ut)(\\|$)"), "rig:C:\\cr, C:\\ut".to_string()),
            (ci(r"^P:[A-Z]:\\Users\\[^\\]+\\AppData\\Local\\Temp\\vmjobs(\\|$)"), "rig:%TEMP%\\vmjobs".to_string()),
            (ci(&format!(r"^P:[A-Z]:\\Windows\\System32\\Tasks\\({RIG_TASKS})$")), "rig:task file".to_string()),
            (ci(&format!(r"^[KVC]:{tc}\\Tree\\({RIG_TASKS})(\\|\||$)")), "rig:TaskCache Tree".to_string()),
            (
                ci(&format!(
                    r"^[VC]:HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\CompatibilityAdapter\\Signatures\|\\?({RIG_TASKS})(\.fp)?$"
                )),
                "rig:task signature".to_string(),
            ),
            (ci(r"^P:[A-Z]:\\Windows\\Prefetch\\RIGTOOL\.EXE-[0-9A-F]+\.pf$"), "rig:rigtool prefetch".to_string()),
            // M1a engine runs (RIG.md section 4a): the engine is the measuring tool here, not the app.
            (
                ci(r"^P:[A-Z]:\\Windows\\Prefetch\\PURGE-ENGINE\.EXE-[0-9A-F]+\.pf$"),
                "rig:purge-engine prefetch".to_string(),
            ),
        ];
        let guids = rig_task_guids(snaps);
        if !guids.is_empty() {
            let alt = guids.iter().map(|g| regex::escape(g)).collect::<Vec<_>>().join("|");
            rules.push((
                ci(&format!(r"^[KVC]:{tc}\\(Tasks|Plain|Logon|Boot|Maintenance)\\({alt})(\\|\||$)")),
                "rig:TaskCache entry".to_string(),
            ));
        }
        RigRules { rules }
    }

    /// Rule name if the canonical target string is rig-owned.
    pub fn check(&self, canon_string: &str) -> Option<&str> {
        self.rules.iter().find(|(re, _)| re.is_match(canon_string)).map(|(_, w)| w.as_str())
    }
}

/// `Id` values of `TaskCache\Tree\<rig task>` keys.
fn rig_task_guids(snaps: &[&Snap]) -> Vec<String> {
    let name_re = ci(&format!(r"^({RIG_TASKS})$"));
    let tree = format!("{TASKCACHE}\\Tree\\");
    let mut out: Vec<String> = Vec::new();
    for s in snaps {
        for (k, r) in &s.keys {
            let ks = k.as_str();
            // `get`: a key with non-ASCII text must not be cut inside a character.
            let Some(rest) = ks.get(tree.len()..).filter(|r| !r.is_empty() && ks[..tree.len()].eq_ignore_ascii_case(&tree)) else {
                continue;
            };
            if rest.contains('\\') || !name_re.is_match(rest) {
                continue;
            }
            if let Some(v) = r.value("Id")
                && !v.preview.is_empty()
                && !out.iter().any(|g| g.eq_ignore_ascii_case(&v.preview))
            {
                out.push(v.preview.clone());
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snap::{write_d, write_f, write_k, write_v};
    use crate::testutil::snap_text;

    #[test]
    fn top_most_collapse_and_values() {
        let s0 = snap_text(|t| {
            write_d(t, "C:\\ProgramData", 0x10, 1, 0);
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(1));
            write_k(t, "HKLM\\SOFTWARE\\Existing", 1, Some(1), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Existing", "Path", 2, 4, 0xaa, "C:\\a");
        });
        let s2 = snap_text(|t| {
            write_d(t, "C:\\ProgramData", 0x10, 2, 0);
            write_d(t, "C:\\ProgramData\\App", 0x10, 2, 0);
            write_d(t, "C:\\ProgramData\\App\\sub", 0x10, 2, 0);
            write_f(t, "C:\\ProgramData\\App\\a.txt", 10, 0x20, 2, 0);
            write_f(t, "C:\\ProgramData\\App\\sub\\b.txt", 5, 0x20, 2, 0);
            write_k(t, "HKLM\\SOFTWARE", 1, Some(0), Some(2));
            write_k(t, "HKLM\\SOFTWARE\\Existing", 2, Some(2), Some(0));
            write_v(t, "HKLM\\SOFTWARE\\Existing", "Path", 2, 8, 0xbb, "C:\\a;C:\\b");
            write_v(t, "HKLM\\SOFTWARE\\Existing", "AppAdded", 1, 4, 0xcc, "x");
            write_k(t, "HKLM\\SOFTWARE\\App", 2, Some(1), Some(1));
            write_v(t, "HKLM\\SOFTWARE\\App", "InNewKey", 1, 4, 0xdd, "y");
            write_k(t, "HKLM\\SOFTWARE\\App\\Sub", 2, Some(0), Some(0));
        });
        let items = derive(&s0, &s2);
        let cs: Vec<String> = items.iter().map(|i| i.target.canon_string()).collect();
        assert_eq!(
            cs,
            vec![
                "P:C:\\ProgramData\\App",
                "K:HKLM\\SOFTWARE\\App",
                "V:HKLM\\SOFTWARE\\Existing|AppAdded",
                "C:HKLM\\SOFTWARE\\Existing|Path",
            ]
        );
        assert_eq!(items[0].size, Some(15));
        match &items[3].target {
            Target::RegValueChanged { before, after, .. } => {
                assert_eq!(before, "C:\\a");
                assert_eq!(after, "C:\\a;C:\\b");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn rig_exclusions() {
        let s = snap_text(|t| {
            let k = format!("{TASKCACHE}\\Tree\\PurgeRigAgent");
            write_k(t, &k, 1, Some(1), Some(0));
            write_v(t, &k, "Id", 1, 78, 1, "{11111111-2222-3333-4444-555555555555}");
        });
        let r = RigRules::new(&[&s]);
        assert!(r.check("P:C:\\cr\\out\\x.json").is_some());
        assert!(r.check("P:C:\\crx").is_none());
        assert!(r.check("P:C:\\Users\\tester\\AppData\\Local\\Temp\\vmjobs\\j1").is_some());
        assert!(r.check("P:C:\\Windows\\System32\\Tasks\\elevate2").is_some());
        assert!(r.check("P:C:\\Windows\\System32\\Tasks\\Mozilla").is_none());
        assert!(r.check(&format!("K:{TASKCACHE}\\Tree\\PurgeRigAgent")).is_some());
        assert!(
            r.check(&format!("C:{TASKCACHE}\\Tasks\\{{11111111-2222-3333-4444-555555555555}}|DynamicInfo")).is_some()
        );
        assert!(r.check(&format!("K:{TASKCACHE}\\Tasks\\{{99999999-2222-3333-4444-555555555555}}")).is_none());
        assert!(
            r.check("V:HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\CompatibilityAdapter\\Signatures|\\PurgeRigAgent.fp")
                .is_some()
        );
    }

    #[test]
    fn rig_exclusions_engine_runs() {
        let s = snap_text(|t| {
            let k = format!("{TASKCACHE}\\Tree\\PurgeRigInstall");
            write_k(t, &k, 1, Some(1), Some(0));
            write_v(t, &k, "Id", 1, 78, 1, "{22222222-2222-3333-4444-555555555555}");
        });
        let r = RigRules::new(&[&s]);
        assert_eq!(r.check("P:C:\\Windows\\Prefetch\\PURGE-ENGINE.EXE-1A2B3C4D.pf"), Some("rig:purge-engine prefetch"));
        assert!(r.check("P:C:\\Windows\\Prefetch\\purge-engine.exe-0123abcd.pf").is_some());
        assert!(r.check("P:C:\\Windows\\Prefetch\\RIGTOOL.EXE-1A2B3C4D.pf").is_some());
        // Only the engine itself: the app's and the vendor uninstaller's traces stay with the app.
        assert!(r.check("P:C:\\Windows\\Prefetch\\PURGE-ENGINE-HELPER.EXE-1A2B3C4D.pf").is_none());
        assert!(r.check("P:C:\\Windows\\Prefetch\\UNINS000.EXE-1A2B3C4D.pf").is_none());
        assert!(r.check("P:C:\\Windows\\Prefetch\\PURGE-ENGINE.EXE-1A2B3C4D.pf\\x").is_none());
        // The medium-integrity install task of vscode-user.
        assert!(r.check("P:C:\\Windows\\System32\\Tasks\\PurgeRigInstall").is_some());
        assert!(r.check(&format!("K:{TASKCACHE}\\Tree\\PurgeRigInstall")).is_some());
        assert!(r.check(&format!("K:{TASKCACHE}\\Plain\\{{22222222-2222-3333-4444-555555555555}}")).is_some());
    }
}
