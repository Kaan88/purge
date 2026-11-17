//! `scanner-coverage`: every location a scanner reads must be captured by the VM rig (ENGINE_PLAN.md
//! §5.6: "a scanner without rig coverage cannot emit Safe"), and the scanners' value containers must be
//! exactly the guard's table of structural containers (§5.10).
//!
//! # Roots
//!
//! For every scanner of `purge_scan::catalog::metadata()`, each declared [`RootSpec`] must lie inside the
//! rig's default capture roots ([`RIG_ROOTS`], vm/RIG.md §2). A pattern is first expanded to the concrete
//! locations it can name ([`expand`]): `*\` is both `HKLM\` and every user hive, `HKCR\` both the
//! machine's and every user's Classes root, `%ProgramFiles%` both Program Files directories, and the
//! profile tokens a profile under `C:\Users`. Each expansion must then be covered by one rig root:
//!
//! - under a **recursive** root, anywhere at or below it, unless the subtree it reads (its depth)
//!   reaches a key the rig excludes ([`RIG_EXCLUDED`]);
//! - under a **depth-1** root, only the root itself read at most one level deep (`depth` 0 or 1), or an
//!   entry directly inside it read as the item alone (`depth` 0).
//!
//! `*` in a pattern is one segment of any name; it is covered only by a `*` in the rig root (a user
//! hive), never by a named key.
//!
//! # Places that must be claimed
//!
//! Each of [`MUST_CLAIM`] (keys the M1b scanners are about: the firewall's rule store, MSI and Burn
//! dependency records) must lie at or under a declared root of some scanner, and the catalog may not
//! shrink below [`MIN_SCANNERS`] scanners and [`MIN_ROOTS`] declared roots (the M1b figures).
//!
//! # Value containers
//!
//! The union of the scanners' `value_containers()` must equal the guard's tables,
//! `purge_guard::containers::all_value_containers()` (`VALUE_CONTAINERS`, then `M1B_VALUE_CONTAINERS`);
//! `purge-scan`'s own unit tests compare the same two lists.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use purge_guard::containers::all_value_containers;
use purge_scan::catalog::{self, ScannerMeta};
use purge_scan::framework::{RootSpec, RootSpecKind};

/// One default capture root of `rigtool snap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RigRoot {
    /// Canonical key or path; `*` is one segment of any name (the loaded user hives).
    pub path: &'static str,
    /// Only the entries directly inside are captured (`@1` in RIG.md), no recursion.
    pub depth1: bool,
}

const fn rec(path: &'static str) -> RigRoot {
    RigRoot {
        path,
        depth1: false,
    }
}

const fn d1(path: &'static str) -> RigRoot {
    RigRoot { path, depth1: true }
}

/// The default capture roots of vm/RIG.md §2, as built by `default_roots()` in
/// vm/rigtool/src/capture.rs (keep the two in step). Paths are those of the rig guests: system drive `C:`,
/// Windows in `C:\Windows`, profiles in `C:\Users`. `HKU\*` stands for every loaded hive, which includes
/// the `<SID>_Classes` hives.
pub const RIG_ROOTS: &[RigRoot] = &[
    rec(r"HKLM\SOFTWARE"),
    rec(r"HKLM\SYSTEM\CurrentControlSet"),
    rec(r"HKU\*"),
    rec(r"C:\Program Files"),
    rec(r"C:\Program Files (x86)"),
    rec(r"C:\ProgramData"),
    rec(r"C:\Users"),
    rec(r"C:\Windows\Installer"),
    rec(r"C:\Windows\Prefetch"),
    rec(r"C:\Windows\System32\Tasks"),
    rec(r"C:\Windows\Tasks"),
    d1(r"C:"),
    d1(r"C:\Windows"),
    d1(r"C:\Windows\System32"),
    d1(r"C:\Windows\SysWOW64"),
    d1(r"C:\Windows\System32\drivers"),
    d1(r"C:\Windows\Fonts"),
];

/// The keys `rigtool snap` leaves out of its default roots (capture.rs `default_roots()`).
pub const RIG_EXCLUDED: &[&str] = &[
    r"HKLM\SYSTEM\CurrentControlSet\Enum",
    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses",
];

/// Places some scanner must declare a root at or above (R3a, M1B-SCAN-INTEG), in root-pattern syntax.
pub const MUST_CLAIM: &[&str] = &[
    r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    r"HKLM\SOFTWARE\Classes\Installer\Dependencies",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
];

/// The fewest scanners the catalog may hold (M1b: 19 + 14).
pub const MIN_SCANNERS: usize = 33;

/// The fewest declared roots the catalog may hold (the M1b catalog's count).
pub const MIN_ROOTS: usize = 97;

/// Whether a declared root of `metas` lies at or above the concrete key `place` (a root pattern `*\`
/// or `HKU\*\` covers `HKLM\` and user places through [`expand`]).
pub fn claimed(place: &str, metas: &[ScannerMeta]) -> bool {
    let place_segs = segments(place);
    metas.iter().any(|meta| {
        meta.captured_roots.iter().any(|root| {
            expand(root).is_some_and(|paths| {
                paths.iter().any(|p| {
                    let r = segments(p);
                    r.len() <= place_segs.len()
                        && r.iter().zip(&place_segs).all(|(r, s)| seg_covers(r, s))
                })
            })
        })
    })
}

/// What the rig captures: its roots and its exclusions.
#[derive(Debug, Clone, Copy)]
pub struct Rig<'a> {
    /// The capture roots.
    pub roots: &'a [RigRoot],
    /// Keys left out of the roots, with their subtrees.
    pub excluded: &'a [&'a str],
}

/// The rig of vm/RIG.md §2.
pub const RIG: Rig<'static> = Rig {
    roots: RIG_ROOTS,
    excluded: RIG_EXCLUDED,
};

/// One declared root the rig does not capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncovered {
    /// The scanner's catalog id.
    pub scanner: &'static str,
    /// The declared root.
    pub root: RootSpec,
    /// Why.
    pub reason: String,
}

/// The `\`-separated segments of a path or key.
fn segments(path: &str) -> Vec<&str> {
    path.split('\\').collect()
}

/// Whether a pattern segment names "any key" rather than one key (`[*]` is the literal key `*`).
fn is_wildcard(seg: &str) -> bool {
    seg.contains('*') && seg != "[*]"
}

/// Whether the rig segment `rig` captures every key the pattern segment `spec` can name.
fn seg_covers(rig: &str, spec: &str) -> bool {
    rig == "*" || (!is_wildcard(spec) && rig.eq_ignore_ascii_case(spec))
}

/// Whether the two segments can name the same key.
fn seg_overlaps(a: &str, b: &str) -> bool {
    is_wildcard(a) || is_wildcard(b) || a.eq_ignore_ascii_case(b)
}

fn strip_prefix_ci<'s>(s: &'s str, prefix: &str) -> Option<&'s str> {
    s.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// The concrete locations a well-formed pattern can name, in the rig's spelling (see the module
/// documentation). `None` when the pattern has no known prefix or token.
pub fn expand(spec: &RootSpec) -> Option<Vec<String>> {
    let p = spec.pattern;
    let bases: &[(&str, &[&str])] = match spec.kind {
        RootSpecKind::Reg => &[
            (r"HKLM\", &[r"HKLM\"]),
            (r"HKU\*\", &[r"HKU\*\"]),
            (r"*\", &[r"HKLM\", r"HKU\*\"]),
            (r"HKCR\", &[r"HKLM\SOFTWARE\Classes\", r"HKU\*_Classes\"]),
        ],
        RootSpecKind::Fs => &[
            (
                "%ProgramFiles%",
                &[r"C:\Program Files", r"C:\Program Files (x86)"],
            ),
            ("%ProgramData%", &[r"C:\ProgramData"]),
            ("%PROFILES%", &[r"C:\Users"]),
            ("%USERPROFILE%", &[r"C:\Users\*"]),
            ("%APPDATA%", &[r"C:\Users\*\AppData\Roaming"]),
            ("%LOCALAPPDATA%", &[r"C:\Users\*\AppData\Local"]),
        ],
    };
    bases.iter().find_map(|(prefix, expansions)| {
        let rest = strip_prefix_ci(p, prefix)?;
        if spec.kind == RootSpecKind::Fs && !(rest.is_empty() || rest.starts_with('\\')) {
            return None;
        }
        Some(expansions.iter().map(|e| format!("{e}{rest}")).collect())
    })
}

/// Why the rig does not capture the concrete location `path` read `depth` levels deep, or `None` when it
/// does.
fn uncovered_reason(path: &str, depth: Option<u32>, rig: &Rig<'_>) -> Option<String> {
    let spec = segments(path);
    let mut why = format!("{path} lies outside every rig capture root");
    for root in rig.roots {
        let r = segments(root.path);
        if r.len() > spec.len() || !r.iter().zip(&spec).all(|(r, s)| seg_covers(r, s)) {
            continue;
        }
        let below = spec.len() - r.len();
        if root.depth1 {
            let fits = match below {
                0 => matches!(depth, Some(0 | 1)),
                1 => depth == Some(0),
                _ => false,
            };
            if fits {
                return None;
            }
            why = format!(
                "{path} (depth {}) reaches below the depth-1 rig root {}",
                depth.map_or_else(|| "all".to_owned(), |d| d.to_string()),
                root.path
            );
            continue;
        }
        return excluded_overlap(&spec, depth, rig.excluded)
            .map(|x| format!("{path} reaches {x}, which the rig excludes"));
    }
    Some(why)
}

/// The first rig exclusion the subtree of `spec` (read `depth` levels deep) can reach.
fn excluded_overlap<'x>(
    spec: &[&str],
    depth: Option<u32>,
    excluded: &[&'x str],
) -> Option<&'x str> {
    excluded.iter().copied().find(|x| {
        let x_segs = segments(x);
        let common = spec.len().min(x_segs.len());
        if !spec[..common]
            .iter()
            .zip(&x_segs[..common])
            .all(|(a, b)| seg_overlaps(a, b))
        {
            return false;
        }
        // Inside the excluded subtree, or the excluded key lies within the levels read.
        spec.len() >= x_segs.len()
            || depth.is_none_or(|d| u32::try_from(x_segs.len() - spec.len()).is_ok_and(|n| n <= d))
    })
}

/// Checks one scanner's declared roots against the rig.
pub fn check_scanner(meta: &ScannerMeta, rig: &Rig<'_>) -> Vec<Uncovered> {
    let mut out = Vec::new();
    for root in &meta.captured_roots {
        let fail = |reason: String| Uncovered {
            scanner: meta.id,
            root: *root,
            reason,
        };
        if !root.is_well_formed() {
            out.push(fail("the pattern is not well formed".into()));
            continue;
        }
        let Some(paths) = expand(root) else {
            out.push(fail("the pattern has no known prefix or token".into()));
            continue;
        };
        out.extend(
            paths
                .iter()
                .filter_map(|p| uncovered_reason(p, root.depth, rig))
                .map(fail),
        );
    }
    out
}

/// Compares the scanners' value containers with the guard's table; one line per difference.
pub fn compare_containers(declared: &[&str], guard: &[&str]) -> Vec<String> {
    let declared: BTreeSet<&str> = declared.iter().copied().collect();
    let guard: BTreeSet<&str> = guard.iter().copied().collect();
    let mut out: Vec<String> = declared
        .difference(&guard)
        .map(|c| format!("{c}: declared by a scanner but not in the guard's VALUE_CONTAINERS"))
        .collect();
    out.extend(
        guard
            .difference(&declared)
            .map(|c| format!("{c}: in the guard's VALUE_CONTAINERS but declared by no scanner")),
    );
    out
}

/// Runs both checks over the catalog; prints each failure. `Ok(false)` when any fails.
pub fn run() -> Result<bool> {
    let metas = catalog::metadata();
    let mut ok = true;
    let mut roots = 0;
    for meta in &metas {
        roots += meta.captured_roots.len();
        for u in check_scanner(meta, &RIG) {
            ok = false;
            eprintln!(
                "scanner-coverage: {}: root {:?} (depth {:?}): {}",
                u.scanner, u.root.pattern, u.root.depth, u.reason
            );
        }
    }

    for place in MUST_CLAIM {
        if !claimed(place, &metas) {
            ok = false;
            eprintln!("scanner-coverage: {place}: no scanner declares a root at or above it");
        }
    }
    if metas.len() < MIN_SCANNERS || roots < MIN_ROOTS {
        ok = false;
        eprintln!(
            "scanner-coverage: the catalog shrank: {} scanners, {roots} roots (at least {MIN_SCANNERS} and \
             {MIN_ROOTS})",
            metas.len()
        );
    }

    let guard: Vec<&str> = all_value_containers().collect();
    if guard.is_empty() {
        bail!("purge_guard::containers holds no value containers");
    }
    let declared = catalog::value_containers();
    for line in compare_containers(&declared, &guard) {
        ok = false;
        eprintln!("scanner-coverage: value containers: {line}");
    }
    for meta in &metas {
        for c in &meta.value_containers {
            if !guard.contains(c) {
                eprintln!("scanner-coverage:   ({c} is declared by {})", meta.id);
            }
        }
    }

    if ok {
        println!(
            "scanner-coverage: {} scanners, {roots} roots inside the rig capture roots; {} places \
             claimed; {} value containers equal the guard's tables",
            metas.len(),
            MUST_CLAIM.len(),
            declared.len()
        );
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(roots: Vec<RootSpec>) -> ScannerMeta {
        ScannerMeta {
            id: "TEST",
            captured_roots: roots,
            value_containers: Vec::new(),
        }
    }

    fn fails(spec: RootSpec, rig: &Rig<'_>) -> bool {
        !check_scanner(&meta(vec![spec]), rig).is_empty()
    }

    #[test]
    fn every_catalog_scanner_is_covered() {
        let metas = catalog::metadata();
        assert!(metas.len() >= 18);
        for m in &metas {
            assert_eq!(check_scanner(m, &RIG), Vec::new(), "{}", m.id);
        }
    }

    #[test]
    fn inside_the_rig_roots() {
        for spec in [
            RootSpec::reg(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                None,
            ),
            RootSpec::reg(r"*\SOFTWARE\Classes", None),
            RootSpec::reg(r"HKCR\Applications", Some(1)),
            RootSpec::reg(r"HKU\*\Environment", Some(0)),
            RootSpec::reg(r"*\SOFTWARE\Classes\[*]\shell", None),
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Services", None),
            RootSpec::fs("%ProgramFiles%", None),
            RootSpec::fs(r"%APPDATA%\Microsoft\Windows\Start Menu", None),
            RootSpec::fs(r"%PROFILES%\Public\Desktop", Some(1)),
            RootSpec::fs("%LOCALAPPDATA%", Some(3)),
        ] {
            assert!(!fails(spec, &RIG), "{spec:?}");
        }
    }

    #[test]
    fn outside_the_rig_roots() {
        for spec in [
            // A deliberately wrong root: HARDWARE is not captured.
            RootSpec::reg(r"HKLM\HARDWARE\DESCRIPTION", None),
            RootSpec::reg(r"HKLM\SYSTEM\Setup", None),
            // `*\SYSTEM` would also be read under HKLM\SYSTEM, which is captured only for the current set.
            RootSpec::reg(r"*\SYSTEM", None),
            // Reaches the excluded Enum subtree.
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet", None),
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\*", None),
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Enum\USB", Some(0)),
            // Not well formed / no token.
            RootSpec::fs(r"C:\Windows\Temp", None),
            RootSpec::reg(r"HKCU\Software", None),
        ] {
            assert!(fails(spec, &RIG), "{spec:?}");
        }
        // The failure names the scanner and the root.
        let wrong = RootSpec::reg(r"HKLM\HARDWARE", None);
        let found = check_scanner(&meta(vec![wrong]), &RIG);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].scanner, found[0].root), ("TEST", wrong));
        assert!(
            found[0].reason.contains(r"HKLM\HARDWARE"),
            "{}",
            found[0].reason
        );
    }

    #[test]
    fn exclusions_are_honoured_only_within_the_depth_read() {
        // The current control set read two levels deep reaches Control\DeviceClasses...
        assert!(fails(
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Control", Some(1)),
            &RIG
        ));
        // ...but its Control key alone does not, and neither does Session Manager.
        assert!(!fails(
            RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Control", Some(0)),
            &RIG
        ));
        assert!(!fails(
            RootSpec::reg(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                Some(0)
            ),
            &RIG
        ));
    }

    #[test]
    fn depth1_roots_are_honoured() {
        // A rig that captures Program Files only one level deep, and the profiles only one level deep.
        let roots = [
            d1(r"C:\Program Files"),
            rec(r"C:\Program Files (x86)"),
            d1(r"C:\Users"),
        ];
        let rig = Rig {
            roots: &roots,
            excluded: &[],
        };
        // The root itself, read one level deep or as the item alone.
        assert!(!fails(RootSpec::fs("%ProgramFiles%", Some(1)), &rig));
        assert!(!fails(RootSpec::fs("%ProgramFiles%", Some(0)), &rig));
        // An entry directly inside, as the item alone.
        assert!(!fails(RootSpec::fs(r"%ProgramFiles%\App", Some(0)), &rig));
        assert!(!fails(RootSpec::fs("%USERPROFILE%", Some(0)), &rig));
        // Deeper than the rig reads.
        assert!(fails(RootSpec::fs("%ProgramFiles%", Some(2)), &rig));
        assert!(fails(RootSpec::fs("%ProgramFiles%", None), &rig));
        assert!(fails(RootSpec::fs(r"%ProgramFiles%\App", Some(1)), &rig));
        assert!(fails(
            RootSpec::fs(r"%ProgramFiles%\App\bin", Some(0)),
            &rig
        ));
        assert!(fails(RootSpec::fs("%USERPROFILE%", Some(1)), &rig));
        assert!(fails(RootSpec::fs("%APPDATA%", Some(0)), &rig));
        // The real rig captures the profiles recursively.
        assert!(!fails(RootSpec::fs("%APPDATA%", None), &RIG));
    }

    #[test]
    fn wildcards_are_covered_only_by_wildcards() {
        let roots = [rec(r"HKLM\SOFTWARE\Classes"), rec(r"HKU\*")];
        let rig = Rig {
            roots: &roots,
            excluded: &[],
        };
        assert!(!fails(RootSpec::reg(r"HKU\*\SOFTWARE", None), &rig));
        assert!(!fails(RootSpec::reg(r"HKCR\Applications", None), &rig));
        // HKLM\SOFTWARE itself is not captured by this rig.
        assert!(fails(RootSpec::reg(r"*\SOFTWARE", None), &rig));
        assert!(!fails(RootSpec::reg(r"*\SOFTWARE\Classes\[*]", None), &RIG));
    }

    #[test]
    fn expansion_spells_both_hives_and_both_program_files() {
        assert_eq!(
            expand(&RootSpec::reg(r"*\SOFTWARE\Run", Some(0))).unwrap(),
            [r"HKLM\SOFTWARE\Run", r"HKU\*\SOFTWARE\Run"]
        );
        assert_eq!(
            expand(&RootSpec::reg(r"HKCR\Applications", Some(1))).unwrap(),
            [
                r"HKLM\SOFTWARE\Classes\Applications",
                r"HKU\*_Classes\Applications"
            ]
        );
        assert_eq!(
            expand(&RootSpec::fs("%programfiles%", None)).unwrap(),
            [r"C:\Program Files", r"C:\Program Files (x86)"]
        );
        assert_eq!(expand(&RootSpec::fs("%ProgramFilesX%", None)), None);
    }

    #[test]
    fn container_differences_are_listed_both_ways() {
        let guard = [r"*\A", r"*\B"];
        assert!(compare_containers(&[r"*\B", r"*\A"], &guard).is_empty());
        let diff = compare_containers(&[r"*\A", r"*\C"], &guard);
        assert_eq!(diff.len(), 2);
        assert!(diff[0].starts_with(r"*\C: declared"), "{diff:?}");
        assert!(diff[1].starts_with(r"*\B: in the guard"), "{diff:?}");
    }

    #[test]
    fn the_real_guard_table_equals_the_scanners_containers() {
        assert!(run().unwrap());
    }

    /// The firewall rule store and the dependency records are claimed by the catalog; a catalog without
    /// the scanner that declares one does not claim it; `*\` roots claim the machine's key.
    #[test]
    fn places_of_the_m1b_scanners_are_claimed() {
        let metas = catalog::metadata();
        for place in MUST_CLAIM {
            assert!(claimed(place, &metas), "{place}");
        }
        // SYS-FIREWALL alone claims the rule store; a scanner of other places does not.
        let only = |id: &str| -> Vec<ScannerMeta> {
            metas.iter().filter(|m| m.id == id).cloned().collect()
        };
        assert!(claimed(MUST_CLAIM[0], &only("SYS-FIREWALL")));
        assert!(!claimed(MUST_CLAIM[0], &only("REG-SOFTWARE")));
        assert!(!claimed(MUST_CLAIM[0], &[]));
        let star = meta(vec![RootSpec::reg(
            r"*\SOFTWARE\Classes\Installer",
            Some(2),
        )]);
        assert!(claimed(
            r"HKLM\SOFTWARE\Classes\Installer\Dependencies",
            std::slice::from_ref(&star)
        ));
        assert!(!claimed(r"HKLM\SOFTWARE\Classes", &[star]));
        let roots: usize = metas.iter().map(|m| m.captured_roots.len()).sum();
        assert!(
            metas.len() >= MIN_SCANNERS && roots >= MIN_ROOTS,
            "{} {roots}",
            metas.len()
        );
    }
}
