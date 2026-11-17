//! Scanner FS-PKGCACHE (ENGINE_PLAN.md §5.6, §5.7.2): the Package Cache directories of a removed WiX Burn
//! bundle and of its removed packages.
//!
//! Burn keeps a copy of a bundle and of each package it installed in a Package Cache
//! (`%ProgramData%\Package Cache` or, per user, `%LOCALAPPDATA%\Package Cache`), one directory per bundle
//! or package. The scanner never lists a Package Cache: it looks only at directories the harvest recorded
//! for the app (`fp.burn.cache_path`, `fp.burn.packages[].cache_dir`, `fp.msi[].source_dirs`), and of
//! those only at one that is, in the guard's canonical form, a **direct child** of the app's own Package
//! Cache root (R3a S4: `%ProgramData%\Package Cache` for a machine entry, the entry user's
//! `%LOCALAPPDATA%\Package Cache` for a per-user one). A Package Cache root itself is never a candidate, and neither is anything deeper. The
//! directory's name must also be the owner's own (R2a S7): the bundle id for `cache_path`, the
//! ProductCode (alone or followed by `v<version>`) for a package's or product's directory; a recorded
//! path naming another bundle's or product's folder gives nothing.
//!
//! # When a directory is offered
//!
//! The directory exists now (a plain directory, not a reparse point), and:
//!
//! - the bundle's directory (`cache_path`): the bundle is gone (`sys_burndeps::bundle_gone`);
//! - a package's directory (`cache_dir`): the bundle is gone, Windows Installer knows the package's
//!   product in no context ([`ScanCtx::product_gone`]), the package had no other dependent at harvest,
//!   and none is known now (the ownership index's dependents of its provider key, other than the bundle's
//!   own entries; an incomplete index is "unknown", and unknown offers nothing);
//! - an MSI product's source directory (`fp.msi[].source_dirs`): the product is gone; when the app is a
//!   Burn bundle, the bundle is gone too, and a source directory that is also a package's directory
//!   follows that package's rule. A directory of a product that some dependency provider named after the
//!   product code still lists other dependents for is not offered.
//!
//! A directory of a package that still has dependents, or whose product is still installed, is never
//! emitted.
//!
//! # What a candidate says
//!
//! `Target::Path` (the canonical directory), `Action::Quarantine`, `Category::Package`, harm Low,
//! `InstallerManifest(Burn)` (the bundle's record) or `InstallerManifest(Msi)` (the product's record),
//! Tier A with Path scope, and the size and file count of the usual bounded walk (`TooLarge` when the walk
//! could not finish). Whether the guard lets the directory through is decided by the plan
//! (`Exemptions::gone_cache_dirs`).
//!
//! # Reads
//!
//! One `metadata()` per recorded directory that passes the rules above, then the bounded walk of that
//! directory. No registry read.

use purge_guard::canon::canon_path;
use purge_guard::prefix;
use purge_model::{Action, BurnFacts, Candidate, Category, Harm, Target};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::fs_installdir::{is_plain_dir, measure, sized};
use crate::sys_burndeps::{bundle_gone, index_other_dependents};

/// The scanner's catalog id.
pub const ID: &str = "FS-PKGCACHE";

/// What the scanner reads: recorded entries of the Package Caches, and what is in them.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(r"%ProgramData%\Package Cache", None),
    RootSpec::fs(r"%LOCALAPPDATA%\Package Cache", None),
];

/// The FS-PKGCACHE scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsPkgCache;

/// Why a recorded directory is the app's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Why {
    /// The bundle's own cache directory.
    Bundle,
    /// The cache directory of a package of the bundle (`{ProductCode}`).
    Package(String),
    /// A source directory of one of the app's MSI products (`{ProductCode}`).
    MsiSource(String),
}

impl Scanner for FsPkgCache {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        let fp = ctx.fp;
        let roots = package_cache_roots(ctx);
        if roots.is_empty() {
            return Vec::new();
        }
        let burn = fp.burn.as_ref();
        let gone = burn.is_some_and(|b| bundle_gone(ctx, b));

        // (canonical directory, reasons), in record order.
        let mut dirs: Vec<(String, Vec<Why>)> = Vec::new();
        let add = |dirs: &mut Vec<(String, Vec<Why>)>, recorded: &str, why: Why| {
            let Some(dir) = cache_entry(recorded, &roots) else {
                return;
            };
            // The folder's name must be the bundle's or the product's own (R2a S7): a recorded path
            // naming another bundle's or product's folder gives nothing.
            let named = prefix::leaf(&dir).is_some_and(|leaf| match &why {
                Why::Bundle => burn.is_some_and(|b| {
                    !b.bundle_id.trim().is_empty() && prefix::eq_ci(leaf, b.bundle_id.trim())
                }),
                Why::Package(code) | Why::MsiSource(code) => is_package_folder(leaf, code),
            });
            if !named {
                return;
            }
            match dirs.iter_mut().find(|(d, _)| prefix::is_same(d, &dir)) {
                Some((_, whys)) => {
                    if !whys.contains(&why) {
                        whys.push(why);
                    }
                }
                None => dirs.push((dir, vec![why])),
            }
        };
        // Directories that must not be offered whatever else names them: a package that is kept.
        let mut kept: Vec<String> = Vec::new();

        if let Some(burn) = burn {
            if gone && let Some(path) = burn.cache_path.as_deref() {
                add(&mut dirs, path, Why::Bundle);
            }
            for package in &burn.packages {
                let Some(path) = package.cache_dir.as_deref() else {
                    continue;
                };
                if gone && package_released(ctx, burn, package) {
                    let code = package.product_code.as_deref().unwrap_or("").trim();
                    add(&mut dirs, path, Why::Package(code.to_owned()));
                } else if let Some(dir) = cache_entry(path, &roots) {
                    kept.push(dir);
                }
            }
        }
        if burn.is_none() || gone {
            for msi in &fp.msi {
                let code = msi.product_code.trim();
                if !ctx.product_gone(code) || !msi_released(ctx, burn, code) {
                    for path in &msi.source_dirs {
                        kept.extend(cache_entry(path, &roots));
                    }
                    continue;
                }
                for path in &msi.source_dirs {
                    add(&mut dirs, path, Why::MsiSource(code.to_owned()));
                }
            }
        }

        let mut out = Vec::new();
        for (dir, whys) in dirs {
            if kept.iter().any(|k| prefix::is_same(k, &dir)) {
                continue;
            }
            let Ok(meta) = ctx.fs.metadata(&dir) else {
                continue;
            };
            if !is_plain_dir(&meta) {
                continue;
            }
            let mut b = ctx.candidate(
                ID,
                Target::Path { path: dir.clone() },
                Action::Quarantine,
                Category::Package,
            );
            for why in &whys {
                b = match (why, burn) {
                    (Why::Bundle, Some(burn)) => b.burn_registration(&burn.bundle_id, "cache_path"),
                    (Why::Package(_), Some(burn)) => {
                        b.burn_registration(&burn.bundle_id, "package_cache_dir")
                    }
                    (Why::MsiSource(code), _) => b.msi_registration(code, "source_dir"),
                    (_, None) => b,
                };
            }
            b.harm(Harm::Low);
            sized(&mut b, &measure(ctx, &dir, &meta));
            b.common_blockers();
            out.push(b.build());
        }
        out
    }
}

/// Whether a package of the bundle lets go of its cache directory: its product is gone, it had no other
/// dependent at harvest, and no other dependent is known now (an incomplete index is unknown: no).
fn package_released(
    ctx: &ScanCtx<'_>,
    burn: &BurnFacts,
    package: &purge_model::BurnPackage,
) -> bool {
    let Some(code) = package.product_code.as_deref() else {
        return false;
    };
    package.other_dependents.is_empty()
        && ctx.product_gone(code)
        && index_other_dependents(ctx, burn, &package.provider_key).is_some_and(|d| d.is_empty())
}

/// Whether nothing known keeps the MSI product `code`: when it is a package of the bundle, that
/// package lets go of it ([`package_released`]); a dependency provider named after the product code has
/// no dependent other than the bundle's own entries (an incomplete index is unknown: no).
fn msi_released(ctx: &ScanCtx<'_>, burn: Option<&BurnFacts>, code: &str) -> bool {
    let empty = BurnFacts {
        bundle_id: String::new(),
        provider_key: None,
        cache_path: None,
        packages: Vec::new(),
        dependents_at_harvest: Vec::new(),
    };
    let facts = burn.unwrap_or(&empty);
    let as_package = facts.packages.iter().filter(|p| {
        p.product_code
            .as_deref()
            .is_some_and(|c| prefix::eq_ci(c.trim(), code))
    });
    for package in as_package {
        if !package_released(ctx, facts, package) {
            return false;
        }
    }
    index_other_dependents(ctx, facts, code).is_some_and(|d| d.is_empty())
}

/// Whether a Package Cache folder name is Burn's folder for the MSI package `product_code` (`{GUID}`):
/// the code itself, or the code followed by `v<version>` (the harvest's rule, `purge_harvest::burn`).
fn is_package_folder(leaf: &str, product_code: &str) -> bool {
    let code = product_code.trim();
    if code.is_empty() {
        return false;
    }
    let (Some(head), Some(rest)) = (leaf.get(..code.len()), leaf.get(code.len()..)) else {
        return false;
    };
    head.eq_ignore_ascii_case(code) && (rest.is_empty() || rest.starts_with(['v', 'V']))
}

/// The Package Cache root of the app's own entry, canonical (R3a S4, the harvest's rule,
/// `purge_harvest::burn`): `%ProgramData%\Package Cache` for a machine entry, the
/// `%LOCALAPPDATA%\Package Cache` of the entry's own user for a per-user one. Another user's Package
/// Cache holds that user's own install, never a leftover of this one. Empty when the folder is not known.
fn package_cache_roots(ctx: &ScanCtx<'_>) -> Vec<String> {
    let guard = ctx.guard;
    let mut out: Vec<String> = Vec::new();
    let base = match ctx.fp.app.program_id.hive_sid() {
        None => Some(guard.program_data.as_str()),
        Some(sid) => guard
            .profiles
            .iter()
            .find(|p| prefix::eq_ci(&p.sid, sid.trim()))
            .map(|p| p.local_appdata.as_str()),
    };
    for base in base.into_iter().filter(|dir| !dir.trim().is_empty()) {
        let input = format!(
            r"{}\Package Cache",
            base.trim().trim_end_matches(prefix::SEP)
        );
        let Ok(canon) = canon_path(&input, guard, None) else {
            continue;
        };
        if canon.needs_long_name {
            continue;
        }
        if !out.iter().any(|have| prefix::is_same(have, &canon.path)) {
            out.push(canon.path);
        }
    }
    out
}

/// The canonical form of a recorded directory when it is a direct child of one of `roots`; `None` for
/// anything else: a root itself, a deeper directory, a path that does not canonicalise (`..`, a device
/// name, a relative path) or that holds an 8.3 short name the guard cannot vouch for.
fn cache_entry(recorded: &str, roots: &[String]) -> Option<String> {
    let trimmed = recorded.trim().trim_end_matches(prefix::SEP);
    let canon = canon_path(trimmed, &purge_guard::canon::GuardEnv::default(), None).ok()?;
    if canon.needs_long_name {
        return None;
    }
    let parent = prefix::parent(&canon.path)?;
    roots
        .iter()
        .any(|root| prefix::is_same(root, parent))
        .then_some(canon.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed() {
        assert!(ROOTS.iter().all(RootSpec::is_well_formed));
    }

    #[test]
    fn only_direct_children_of_a_root_are_entries() {
        let roots = vec![
            r"C:\ProgramData\Package Cache".to_owned(),
            r"C:\Users\tester\AppData\Local\Package Cache".to_owned(),
        ];
        let entry = r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.0";
        assert_eq!(cache_entry(entry, &roots).as_deref(), Some(entry));
        assert_eq!(
            cache_entry(&format!(r"{entry}\"), &roots).as_deref(),
            Some(entry)
        );
        assert!(cache_entry(r"c:\users\tester\appdata\local\package cache\{B}", &roots).is_some());
        for bad in [
            r"C:\ProgramData\Package Cache",
            r"C:\ProgramData\Package Cache\",
            r"C:\ProgramData\Package Cache\..\x",
            r"C:\ProgramData\Package Cache\{B}\sub",
            r"C:\ProgramData\x",
            r"C:\ProgramData\PACKAG~1\{B}",
            r"Package Cache\{B}",
            r"\\server\share\Package Cache\{B}",
            "",
        ] {
            assert_eq!(cache_entry(bad, &roots), None, "{bad}");
        }
    }
}
