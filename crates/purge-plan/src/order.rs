//! The order of a plan's items (ENGINE_PLAN.md §7.1). Deterministic: the same set of candidates sorts the
//! same way whatever order the scanners produced them in.
//!
//! [`SortKey`] orders, most significant first:
//!
//! 1. **Stage** ([`Stage`]): scheduled tasks and firewall rules first, then registry values and value
//!    segments, then registry keys, then files and directories, then service deletes, then packages.
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

/// The stage of §7.1 an item belongs to, in run order (the derived `Ord` is the order of the variants).
///
/// How the stages map onto the order of §7.1:
///
/// | §7.1 step | Stage |
/// |---|---|
/// | 1, 2: close processes, stop services | not plan items (the executor's prepare step) |
/// | 3: tasks, firewall | [`Stage::Task`], [`Stage::FirewallRule`] |
/// | 4, 5: shell/COM/associations; registry values, then keys | [`Stage::RegistryValue`], [`Stage::RegistryKey`] |
/// | 6, 7: shortcuts; files, then folders | [`Stage::FileSystem`] |
/// | 8: delete services | [`Stage::Service`] |
/// | 9: AppX | [`Stage::Package`] |
/// | 10: prune empty parents | inside each stage (see the module docs) |
///
/// Three steps of §7.1 are not separate stages, because making them so would reorder plans the M1a
/// engine already wrote (their hashes are gate evidence): shell, COM and association keys are ordered
/// with the other registry items by depth; shortcuts with the other files; and a delete-if-empty
/// container comes right after the items at its depth in its own stage, not after every stage. No
/// scanner emits tasks, firewall rules or services yet (M1b), so their place could be aligned with §7.1
/// without changing any existing plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    /// A scheduled task (§7.1 step 3).
    Task,
    /// A firewall rule (§7.1 step 3).
    FirewallRule,
    /// A registry value or a segment of one.
    RegistryValue,
    /// A registry key.
    RegistryKey,
    /// A file or directory.
    FileSystem,
    /// A service delete (§7.1 step 8: after the files its image lives in).
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
        // Tasks and firewall rules first (§7.1 step 3).
        "task",
        "fw",
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
        // Service deletes after the files (§7.1 step 8), packages last.
        "svc",
        "pkg",
    ];

    fn ids(list: &[Candidate]) -> Vec<&str> {
        list.iter().map(|c| c.id.0.as_str()).collect()
    }

    #[test]
    fn stages_children_first_and_tasks_firewall_first_services_after_files() {
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
        assert_eq!(Stage::of(&Target::Task { path: "t".into() }), Stage::Task);
        assert_eq!(
            Stage::of(&Target::FirewallRule { id: "f".into() }),
            Stage::FirewallRule
        );
        assert_eq!(
            Stage::of(&Target::Service { name: "s".into() }),
            Stage::Service
        );
        assert_eq!(
            Stage::of(&Target::AppxPackage {
                full_name: "p".into()
            }),
            Stage::Package
        );
    }

    /// The stage order is ENGINE_PLAN.md §7.1 for the steps that are stages: tasks and firewall rules
    /// (step 3) before registry values and keys (step 5), files (step 7) before service deletes (step 8),
    /// AppX (step 9) last.
    #[test]
    fn stage_order_follows_plan_7_1() {
        let in_order = [
            Stage::Task,
            Stage::FirewallRule,
            Stage::RegistryValue,
            Stage::RegistryKey,
            Stage::FileSystem,
            Stage::Service,
            Stage::Package,
        ];
        for pair in in_order.windows(2) {
            assert!(pair[0] < pair[1], "{:?} before {:?}", pair[0], pair[1]);
        }
    }

    /// The stage order of M1a, before tasks and firewall rules moved ahead of the registry.
    fn m1a_stage_rank(stage: Stage) -> u8 {
        match stage {
            Stage::RegistryValue => 0,
            Stage::RegistryKey => 1,
            Stage::FileSystem => 2,
            Stage::Task => 3,
            Stage::FirewallRule => 4,
            Stage::Service => 5,
            Stage::Package => 6,
        }
    }

    /// Moving tasks and firewall rules changes nothing for a plan without them: every M1a plan (no scanner
    /// emits tasks or firewall rules) keeps its order, so its plan hash stays the same.
    #[test]
    fn plans_without_tasks_or_firewall_rules_keep_the_m1a_order() {
        let mut base: Vec<Candidate> = sample()
            .into_iter()
            .filter(|c| !matches!(c.target, Target::Task { .. } | Target::FirewallRule { .. }))
            .collect();
        // More shapes: a report-only file beside the removal, a second service, a value of a deeper key.
        let mut report = cand("report", path(r"C:\Program Files\Vendor\App\log.txt"), "X");
        report.action = Action::ReportOnly;
        base.push(report);
        base.push(cand(
            "svc-b",
            Target::Service {
                name: "AnotherSvc".into(),
            },
            "SYS",
        ));
        base.push(cand(
            "deep-value",
            value(r"HKLM\SOFTWARE\Vendor\App\Settings\Deep", "x"),
            "REF-ANY",
        ));
        let n = base.len();
        for (mul, add) in [(1, 0), (3, 1), (5, 2), (7, 4), (11, 3), (13, 6)] {
            let mut new: Vec<Candidate> =
                (0..n).map(|i| base[(i * mul + add) % n].clone()).collect();
            let mut old = new.clone();
            sort(&mut new);
            old.sort_by_cached_key(|c| (m1a_stage_rank(Stage::of(&c.target)), sort_key(c)));
            assert_eq!(ids(&new), ids(&old), "permutation {mul}x+{add}");
        }
    }
}
