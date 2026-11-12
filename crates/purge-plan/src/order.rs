//! The order of a plan's items (ENGINE_PLAN.md §7.1). Deterministic: the same set of candidates sorts the
//! same way whatever order the scanners produced them in.
//!
//! [`SortKey`] orders, most significant first:
//!
//! 1. **Stage**: registry values and value segments, then registry keys, then files and directories, then
//!    API objects (tasks, firewall rules, services, packages) last.
//! 2. **Depth, deepest first**: children before parents, so a key or directory is reached only after
//!    everything offered inside it. A file is always deeper than the directories that hold it, which gives
//!    "files before folders" without knowing which path is which.
//! 3. **Whole removals before delete-if-empty** at the same depth, so that a container is pruned after its
//!    siblings went.
//! 4. The case-folded path, then the value name, segment and segment position, then the action, the
//!    scanner and the candidate id as tie-breakers that make the key total.
//!
//! Folding uses the same rule as every prefix test of the engine (`purge_guard::prefix::fold`).

use purge_guard::prefix;
use purge_model::{Action, Candidate, Target};

/// The stage of §7.1 an item belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    /// A registry value or a segment of one.
    RegistryValue,
    /// A registry key.
    RegistryKey,
    /// A file or directory.
    FileSystem,
    /// A scheduled task.
    Task,
    /// A firewall rule.
    FirewallRule,
    /// A service.
    Service,
    /// An AppX/MSIX package.
    Package,
}

impl Stage {
    /// The stage of a target.
    #[must_use]
    pub fn of(target: &Target) -> Stage {
        match target {
            Target::RegValue { .. }
            | Target::RegValueChanged { .. }
            | Target::RegMultiSzSegment { .. } => Stage::RegistryValue,
            Target::RegKey { .. } => Stage::RegistryKey,
            Target::Path { .. } => Stage::FileSystem,
            Target::Task { .. } => Stage::Task,
            Target::FirewallRule { .. } => Stage::FirewallRule,
            Target::Service { .. } => Stage::Service,
            Target::AppxPackage { .. } => Stage::Package,
        }
    }
}

/// The sort key of one candidate. Compare with `Ord`; smaller runs first.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SortKey {
    stage: Stage,
    /// Deepest first.
    depth: std::cmp::Reverse<usize>,
    /// 0 for a removal, 1 for delete-if-empty, 2 for report-only.
    prune: u8,
    /// Case-folded segments of the path, key, task path, or the single name of an API object.
    path: Vec<String>,
    /// Case-folded value name, for value targets.
    name: String,
    /// The segment text and position, for segment targets.
    segment: (String, Option<u32>),
    action: u8,
    scanner: String,
    id: String,
}

fn action_rank(action: Action) -> u8 {
    match action {
        Action::DeleteValue => 0,
        Action::EditSegment => 1,
        Action::DeleteKey => 2,
        Action::Quarantine => 3,
        Action::RemovePackage => 4,
        Action::RemoveDirIfEmpty => 5,
        Action::ReportOnly => 6,
    }
}

/// The sort key of `candidate`.
#[must_use]
pub fn sort_key(candidate: &Candidate) -> SortKey {
    let segments = |p: &str| prefix::segments(p).map(prefix::fold).collect::<Vec<_>>();
    let (path, name, segment) = match &candidate.target {
        Target::Path { path } | Target::RegKey { path } | Target::Task { path } => {
            (segments(path), String::new(), (String::new(), None))
        }
        Target::RegValue { path, name } | Target::RegValueChanged { path, name, .. } => {
            (segments(path), prefix::fold(name), (String::new(), None))
        }
        Target::RegMultiSzSegment {
            path,
            name,
            segment,
            index,
        } => (
            segments(path),
            prefix::fold(name),
            (prefix::fold(segment), *index),
        ),
        Target::Service { name } => (
            vec![prefix::fold(name)],
            String::new(),
            (String::new(), None),
        ),
        Target::FirewallRule { id } => {
            (vec![prefix::fold(id)], String::new(), (String::new(), None))
        }
        Target::AppxPackage { full_name } => (
            vec![prefix::fold(full_name)],
            String::new(),
            (String::new(), None),
        ),
    };
    SortKey {
        stage: Stage::of(&candidate.target),
        depth: std::cmp::Reverse(path.len()),
        prune: match candidate.action {
            Action::RemoveDirIfEmpty => 1,
            Action::ReportOnly => 2,
            _ => 0,
        },
        path,
        name,
        segment,
        action: action_rank(candidate.action),
        scanner: candidate.scanner.clone(),
        id: candidate.id.0.clone(),
    }
}

/// Sorts `candidates` into plan order.
pub fn sort(candidates: &mut [Candidate]) {
    candidates.sort_by_cached_key(sort_key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::testkit::*;

    fn sample() -> Vec<Candidate> {
        let app = r"HKLM\SOFTWARE\Vendor\App";
        let mut vendor_key = cand("vendor-key", key(r"HKLM\SOFTWARE\Vendor"), "REG-SOFTWARE");
        vendor_key.action = Action::RemoveDirIfEmpty;
        let mut vendor_dir = cand(
            "vendor-dir",
            path(r"C:\Program Files\Vendor"),
            "FS-VENDORPARENT",
        );
        vendor_dir.action = Action::RemoveDirIfEmpty;
        let mut sibling_dir = cand("empty-sibling", path(r"C:\Program Files\Vendor\Empty"), "X");
        sibling_dir.action = Action::RemoveDirIfEmpty;
        let segment = Target::RegMultiSzSegment {
            path: r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment".into(),
            name: "Path".into(),
            segment: r"C:\Program Files\Vendor\App\bin".into(),
            index: None,
        };
        vec![
            cand(
                "pkg",
                Target::AppxPackage {
                    full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
                },
                "SYS-APPX",
            ),
            vendor_dir,
            cand(
                "svc",
                Target::Service {
                    name: "AppSvc".into(),
                },
                "SYS",
            ),
            cand(
                "app-dir",
                path(r"C:\Program Files\Vendor\App"),
                "FS-INSTALLDIR",
            ),
            sibling_dir,
            cand(
                "file",
                path(r"C:\Program Files\Vendor\App\app.exe"),
                "FS-INSTALLDIR",
            ),
            vendor_key,
            cand("app-key", key(app), "REG-SOFTWARE"),
            cand(
                "sub-key",
                key(r"HKLM\SOFTWARE\Vendor\App\Settings"),
                "REG-SOFTWARE",
            ),
            cand("value-b", value(app, "Zeta"), "REF-ANY"),
            cand("value-a", value(app, "alpha"), "REF-ANY"),
            cand("value-default", value(app, ""), "REF-ANY"),
            cand("segment", segment, "REG-ENV"),
            cand(
                "task",
                Target::Task {
                    path: r"\Vendor\Update".into(),
                },
                "SYS",
            ),
            cand("fw", Target::FirewallRule { id: "{1}".into() }, "SYS"),
        ]
    }

    const EXPECTED: [&str; 15] = [
        // Values, deepest key first; within one key by name.
        "segment",
        "value-default",
        "value-a",
        "value-b",
        // Keys, deepest first; the delete-if-empty vendor key last.
        "sub-key",
        "app-key",
        "vendor-key",
        // Files before the directories above them; a delete-if-empty sibling after the removal.
        "file",
        "app-dir",
        "empty-sibling",
        "vendor-dir",
        // API objects last.
        "task",
        "fw",
        "svc",
        "pkg",
    ];

    fn ids(list: &[Candidate]) -> Vec<&str> {
        list.iter().map(|c| c.id.0.as_str()).collect()
    }

    #[test]
    fn stages_children_first_and_api_objects_last() {
        let mut list = sample();
        sort(&mut list);
        assert_eq!(ids(&list), EXPECTED);
    }

    /// Any input order gives the same output order.
    #[test]
    fn shuffled_input_sorts_the_same() {
        let base = sample();
        let n = base.len();
        // A fixed multiplicative walk over the indexes stands in for a random shuffle: 15 is coprime to
        // each multiplier, so every round is a permutation.
        for (mul, add) in [
            (1, 0),
            (2, 3),
            (4, 1),
            (7, 5),
            (8, 11),
            (11, 2),
            (13, 7),
            (14, 14),
        ] {
            let mut list: Vec<Candidate> =
                (0..n).map(|i| base[(i * mul + add) % n].clone()).collect();
            sort(&mut list);
            assert_eq!(ids(&list), EXPECTED, "permutation {mul}x+{add}");
        }
        let mut reversed: Vec<Candidate> = base.into_iter().rev().collect();
        sort(&mut reversed);
        assert_eq!(ids(&reversed), EXPECTED);
    }

    #[test]
    fn key_is_case_insensitive_and_total() {
        let a = cand("a", key(r"HKLM\SOFTWARE\Vendor\App"), "S1");
        let b = cand("b", key(r"hklm\software\VENDOR\app\"), "S1");
        let (ka, kb) = (sort_key(&a), sort_key(&b));
        assert_ne!(ka, kb, "the id still tells them apart");
        assert!(ka < kb);
        let mut same = b.clone();
        same.id = a.id.clone();
        assert_eq!(sort_key(&same), ka);
        // Two candidates on one target differ by action, then scanner.
        let mut prune = a.clone();
        prune.action = Action::RemoveDirIfEmpty;
        assert!(ka < sort_key(&prune));
        let mut other_scanner = a.clone();
        other_scanner.scanner = "S2".into();
        assert!(ka < sort_key(&other_scanner));
        // Segments of one value order by text, then position.
        let seg = |text: &str, index| {
            cand(
                "s",
                Target::RegMultiSzSegment {
                    path: r"HKLM\X".into(),
                    name: "Path".into(),
                    segment: text.into(),
                    index,
                },
                "REG-ENV",
            )
        };
        assert!(sort_key(&seg("a", Some(3))) < sort_key(&seg("b", Some(1))));
        assert!(sort_key(&seg("a", None)) < sort_key(&seg("a", Some(0))));
        assert!(sort_key(&seg("a", Some(0))) < sort_key(&seg("a", Some(1))));
    }

    #[test]
    fn stage_of_each_target() {
        assert_eq!(Stage::of(&value("k", "v")), Stage::RegistryValue);
        assert_eq!(Stage::of(&key("k")), Stage::RegistryKey);
        assert_eq!(Stage::of(&path("p")), Stage::FileSystem);
        assert!(Stage::RegistryValue < Stage::RegistryKey);
        assert!(Stage::RegistryKey < Stage::FileSystem);
        assert!(Stage::FileSystem < Stage::Task);
        assert!(Stage::Service < Stage::Package);
    }
}
