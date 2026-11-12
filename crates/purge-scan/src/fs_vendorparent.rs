//! FS-VENDORPARENT (ENGINE_PLAN.md §5.6): vendor folders, offered delete-if-empty with the pending
//! `EmptyAfterPlan` marker.
//!
//! A directory directly under `%APPDATA%`, `%LOCALAPPDATA%`, LocalLow, `%ProgramData%`, a Program Files
//! directory or a `Start Menu\Programs` directory whose name is one of the app's vendor aliases
//! (`Roaming\Mozilla`, `Program Files\Mozilla`) is the vendor's container, not the app's folder: other
//! products of the vendor may live in it. So is one whose name is a vendor alias decorated with a
//! machine id (`ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38`). It is therefore only ever
//! offered as `Action::RemoveDirIfEmpty`, with `VendorContainer` evidence that carries the pending marker
//! and the complete listing of its direct children. `purge-plan` decides from that listing whether the
//! rest of the plan empties it (§7.1).
//!
//! # Empty parents
//!
//! Under the application-data bases FS-APPDATA offers directories named after a harvested token below a
//! vendor folder (`Mozilla-<guid>\updates\<install hash>`). A directory between the vendor folder and
//! such a directory (`updates`) is offered in the same way, delete-if-empty with its complete listing
//! (§6 "owned descendants plus empty parents", §7.1 step 10): otherwise the vendor folder would keep a
//! subdirectory the plan never removes and could not be found empty. The listing is the only thing that
//! lets it go: a file or a directory of another product in it keeps it, and with it the vendor folder.
//!
//! Never offered:
//!
//! - the container of a mega-vendor (`Microsoft`, `Google`…): too many unrelated products share it;
//! - a directory of clean Windows (the baseline of this build has it);
//! - a directory that could not be listed completely: a missing child would make it look empty;
//! - a directory that is one of the app's own roots (FS-INSTALLDIR's) or that carries the app's full
//!   name (FS-APPDATA's or FS-SHORTCUTS'), and a reparse point.

use purge_guard::prefix;
use purge_identity::identity::IdentityMatch;
use purge_model::{Action, Candidate, Category, RootKind, Target};
use purge_source::types::DirEntry;

use crate::framework::{AppIdentityView, ContainerChild, RootSpec, ScanCtx, Scanner};
use crate::fs_installdir::{Places, emit, is_plain_dir, join, list};

/// The scanner's catalog id.
pub const ID: &str = "FS-VENDORPARENT";

/// How deep below an application-data base FS-APPDATA looks for token-named directories (its
/// `TOKEN_DEPTH`). The empty parents offered here end one level above.
const TOKEN_DEPTH: u32 = 3;

/// The locations the scanner reads. Below the application-data bases the parents of token-named
/// directories are read as deep as FS-APPDATA looks for those.
const ROOTS: &[RootSpec] = &[
    RootSpec::fs(r"%APPDATA%", Some(TOKEN_DEPTH)),
    RootSpec::fs(r"%LOCALAPPDATA%", Some(TOKEN_DEPTH)),
    RootSpec::fs(r"%USERPROFILE%\AppData\LocalLow", Some(TOKEN_DEPTH)),
    RootSpec::fs(r"%ProgramFiles%", Some(1)),
    RootSpec::fs(r"%ProgramData%", Some(TOKEN_DEPTH)),
    RootSpec::fs(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs", Some(1)),
    RootSpec::fs(
        r"%ProgramData%\Microsoft\Windows\Start Menu\Programs",
        Some(1),
    ),
];

/// Characters that may separate a vendor alias from the machine id that decorates it.
const DECORATION_SEPARATORS: [char; 4] = ['-', '_', '.', ' '];

/// The fewest hex digits of a machine id (§5.3 `HarvestedToken`: "GUID or ≥ 12-hex token").
const MIN_ID_HEX_DIGITS: usize = 12;

/// The FS-VENDORPARENT scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsVendorParent;

/// The kind of a base directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// `%APPDATA%`, `%LOCALAPPDATA%`, LocalLow or `%ProgramData%`: FS-APPDATA offers token-named
    /// directories below a vendor folder here, so their parents are offered too.
    AppData,
    /// A Program Files or `Start Menu\Programs` directory.
    Other,
}

impl Scanner for FsVendorParent {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        if app.identity.mega_vendor() {
            return out;
        }
        let places = Places::of(ctx);
        // (base, category of a vendor folder there, kind)
        let mut bases: Vec<(&str, Category, Base)> = places
            .appdata_bases()
            .into_iter()
            .map(|base| (base, Category::AppData, Base::AppData))
            .collect();
        bases.extend(
            places
                .program_files
                .iter()
                .map(|dir| (dir.as_str(), Category::AppFiles, Base::Other)),
        );
        for dir in [&places.programs, &places.common_programs]
            .into_iter()
            .flatten()
        {
            if !bases.iter().any(|(base, ..)| prefix::is_same(base, dir)) {
                bases.push((dir, Category::AppFiles, Base::Other));
            }
        }
        for (base, category, kind) in bases {
            vendor_folders(ctx, app, base, category, kind, &mut out);
        }
        out
    }
}

/// Whether `text` is a machine-made id: a GUID (braced or not) or dash-separated groups of hex digits,
/// with at least [`MIN_ID_HEX_DIGITS`] hex digits and a decimal digit among them. A word that happens to
/// consist of the letters a-f is not an id.
fn is_machine_id(text: &str) -> bool {
    let inner = text
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .unwrap_or(text);
    let mut digits = 0;
    let mut decimal = false;
    for group in inner.split('-') {
        if group.is_empty() || !group.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        digits += group.len();
        decimal |= group.chars().any(|c| c.is_ascii_digit());
    }
    decimal && digits >= MIN_ID_HEX_DIGITS
}

/// The part of a directory name in front of the machine id that decorates it: `Mozilla` for
/// `Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38`. `None` for a name that is not
/// `<stem><separator><id>`.
fn decorated_stem(name: &str) -> Option<&str> {
    name.char_indices()
        .filter(|(_, c)| DECORATION_SEPARATORS.contains(c))
        .find_map(|(at, c)| {
            let (stem, id) = (&name[..at], &name[at + c.len_utf8()..]);
            (!stem.trim().is_empty() && is_machine_id(id)).then_some(stem)
        })
}

/// The vendor alias a directory name stands for: the name itself, or the stem of a name decorated with
/// a machine id.
fn vendor_of(app: &AppIdentityView, name: &str) -> Option<IdentityMatch> {
    app.identity
        .matches_vendor(name)
        .or_else(|| app.identity.matches_vendor(decorated_stem(name)?))
}

/// Whether `name` is one of the app's harvested tokens: such a directory is FS-APPDATA's to offer.
fn token_named(ctx: &ScanCtx<'_>, name: &str) -> bool {
    ctx.fp.tokens.iter().any(|t| prefix::eq_ci(&t.token, name))
}

/// Whether `path` is one of the app's own roots or lies in one (FS-INSTALLDIR's), or is a path the Inno
/// log names (FS-APPDATA's).
fn offered_elsewhere(ctx: &ScanCtx<'_>, path: &str) -> bool {
    let in_root =
        ctx.fp.roots.iter().any(|r| {
            r.kind != RootKind::ReferencedDataDir && prefix::is_same_or_inside(path, &r.path)
        });
    in_root
        || ctx
            .fp
            .inno
            .iter()
            .any(|r| matches!(&r.target, Target::Path { path: p } if prefix::is_same(p, path)))
}

/// Offers `path` as a delete-if-empty container with the pending marker and the listing of its direct
/// children, and returns that listing. `None`, and nothing offered, for a directory of clean Windows,
/// for one inside another app, and for one that cannot be listed completely: an incomplete listing must
/// not pass as complete.
fn offer(
    ctx: &ScanCtx<'_>,
    vendor: &IdentityMatch,
    path: &str,
    category: Category,
    out: &mut Vec<Candidate>,
) -> Option<Vec<DirEntry>> {
    let target = Target::Path {
        path: path.to_owned(),
    };
    if ctx.in_baseline(&target) {
        return None;
    }
    // Every direct child, or nothing.
    let children = list(ctx, path)?;
    let listing = children.iter().map(|child| {
        if child.meta.is_dir() {
            ContainerChild::Container(&child.name)
        } else {
            ContainerChild::Leaf(&child.name)
        }
    });
    let mut b = ctx.candidate(ID, target, Action::RemoveDirIfEmpty, category);
    if !b.vendor_container_pending(vendor, listing) {
        return None;
    }
    b.child_count(u32::try_from(children.len()).unwrap_or(u32::MAX))
        .common_blockers();
    emit(out, b).then_some(children)
}

/// Offers the vendor directories directly under `base`: those named after a vendor alias and those
/// named after one and decorated with a machine id.
fn vendor_folders(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    base: &str,
    category: Category,
    kind: Base,
    out: &mut Vec<Candidate>,
) {
    let Some(entries) = list(ctx, base) else {
        return;
    };
    for entry in &entries {
        if !is_plain_dir(&entry.meta) {
            continue;
        }
        let Some(vendor) = vendor_of(app, &entry.name) else {
            continue;
        };
        if vendor.weight <= 0 || app.identity.matches_full_name(&entry.name).is_some() {
            continue;
        }
        let path = join(base, &entry.name);
        let own_root = ctx
            .fp
            .roots
            .iter()
            .any(|r| r.kind != RootKind::ReferencedDataDir && prefix::is_same(&r.path, &path));
        if own_root {
            continue;
        }
        let Some(children) = offer(ctx, &vendor, &path, category, out) else {
            continue;
        };
        if kind == Base::AppData {
            let folder = VendorFolder {
                vendor: &vendor,
                name: &entry.name,
            };
            empty_parents(ctx, app, &folder, &path, &children, 2, out);
        }
    }
}

/// The vendor folder whose subdirectories [`empty_parents`] looks at.
struct VendorFolder<'a> {
    /// The alias the folder is named after.
    vendor: &'a IdentityMatch,
    /// The folder's own name.
    name: &'a str,
}

/// Whether a token-named directory lies below `dir`, whose children are `depth` levels below the base,
/// as deep as FS-APPDATA looks for one.
fn leads_to_token(ctx: &ScanCtx<'_>, dir: &str, depth: u32) -> bool {
    let Some(children) = list(ctx, dir) else {
        return false;
    };
    children.iter().any(|child| {
        is_plain_dir(&child.meta)
            && (token_named(ctx, &child.name)
                || (depth < TOKEN_DEPTH && leads_to_token(ctx, &join(dir, &child.name), depth + 1)))
    })
}

/// Offers the empty parents of the app's token-named directories (see the module documentation): each
/// subdirectory of `dir` that lies between the vendor folder and a directory named after a harvested
/// token.
///
/// `children` are the entries of `dir`, `depth` levels below the base. A subdirectory another scanner
/// offers whole (token-named, product-named, an own root, an Inno path) is left to that scanner.
fn empty_parents(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    folder: &VendorFolder<'_>,
    dir: &str,
    children: &[DirEntry],
    depth: u32,
    out: &mut Vec<Candidate>,
) {
    if depth >= TOKEN_DEPTH {
        return;
    }
    for child in children {
        if !is_plain_dir(&child.meta) || token_named(ctx, &child.name) {
            continue;
        }
        let named = app.identity.matches_full_name(&child.name).is_some()
            || app
                .identity
                .matches_product_subfolder(folder.name, &child.name)
                .is_some();
        let path = join(dir, &child.name);
        if named || offered_elsewhere(ctx, &path) || !leads_to_token(ctx, &path, depth + 1) {
            continue;
        }
        let Some(inner) = offer(ctx, folder.vendor, &path, Category::AppData, out) else {
            continue;
        };
        empty_parents(ctx, app, folder, &path, &inner, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::testkit::{EDITION, World, baseline};
    use crate::framework::{CHILDREN_KEY, PENDING_KEY, PENDING_VALUE};
    use purge_model::{Blocker, EvidenceKind, Harm, HarvestedToken, SourceId};
    use purge_source::fixture::{Fixture, FixtureBuilder};

    const HASH: &str = "308046B0AF4A39CB";
    const OTHER_HASH: &str = "D78BF5DD33499EC2";
    const SHARED: &str = r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38";
    const ROAMING: &str = r"C:\Users\tester\AppData\Roaming";

    fn machine() -> FixtureBuilder {
        Fixture::builder()
            .volume("C:\\", Some(0x1234_5678), true, "NTFS")
            .dir(r"C:\Program Files")
            .dir(r"C:\ProgramData")
            .dir(ROAMING)
            .dir(r"C:\Users\tester\AppData\Local")
    }

    /// A world for an uninstalled Firefox with the install hash as its harvested token.
    fn firefox(fixture: Fixture) -> World {
        let mut world = World::new(fixture);
        world.fp.app.display_name = "Mozilla Firefox (x64 en-US)".into();
        world.fp.identity.names = vec!["Mozilla Firefox".into(), "Firefox".into()];
        world.fp.identity.vendors = vec!["Mozilla".into()];
        world.fp.identity.tokens = vec!["firefox".into()];
        world.fp.roots[0].path = r"C:\Program Files\Mozilla Firefox".into();
        world.fp.tokens = vec![HarvestedToken {
            token: HASH.into(),
            source: SourceId("aumid".into()),
        }];
        world.env = [
            ("PROGRAMDATA", r"C:\ProgramData"),
            ("USERPROFILE", r"C:\Users\tester"),
            ("APPDATA", ROAMING),
            ("LOCALAPPDATA", r"C:\Users\tester\AppData\Local"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        world
    }

    fn scan(world: &World) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        FsVendorParent.scan(&world.ctx(), &app)
    }

    fn paths(found: &[Candidate]) -> Vec<&str> {
        found
            .iter()
            .map(|c| match &c.target {
                Target::Path { path } => path.as_str(),
                other => panic!("not a path: {other:?}"),
            })
            .collect()
    }

    fn listing(c: &Candidate) -> &str {
        c.evidence[0].detail.get(CHILDREN_KEY).unwrap()
    }

    #[test]
    fn machine_ids() {
        for id in [
            "1de4eec8-1241-4177-a864-e594e8d1fb38",
            "{1DE4EEC8-1241-4177-A864-E594E8D1FB38}",
            "308046B0AF4A39CB",
        ] {
            assert!(is_machine_id(id), "{id}");
        }
        for word in [
            "",
            "Firefox",
            "deadbeefcafe",
            "1234",
            "2024-10",
            "1de4eec8--1241-4177-a864-e594e8d1fb38",
            "{1de4eec8-1241-4177-a864-e594e8d1fb38",
            "308046B0AF4A39CB.bak",
        ] {
            assert!(!is_machine_id(word), "{word}");
        }
        assert_eq!(
            decorated_stem("Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38"),
            Some("Mozilla")
        );
        assert_eq!(
            decorated_stem("Mozilla Corporation_308046B0AF4A39CB"),
            Some("Mozilla Corporation")
        );
        for plain in [
            "Mozilla",
            "Mozilla-Tools",
            "Mozilla-2024",
            "-308046B0AF4A39CB",
        ] {
            assert_eq!(decorated_stem(plain), None, "{plain}");
        }
    }

    /// The firefox run of M1A_REPLAY.md: `ProgramData\Mozilla-<guid>` holds two files and
    /// `updates\<install hash>`. The folder and `updates` are offered delete-if-empty with complete
    /// listings; the token-named directory and the files are not this scanner's.
    #[test]
    fn decorated_vendor_folder_and_the_parents_of_token_dirs_are_offered() {
        let fixture = machine()
            .file(&format!(r"{SHARED}\profile_count_{HASH}.json"), 78)
            .file(&format!(r"{SHARED}\updates\{HASH}\update-config.json"), 78)
            .dir(&format!(r"{SHARED}\updates\{HASH}\updates\0"))
            .build();
        let found = scan(&firefox(fixture));
        let updates = format!(r"{SHARED}\updates");
        assert_eq!(paths(&found), [SHARED, updates.as_str()]);
        for c in &found {
            assert_eq!(c.action, Action::RemoveDirIfEmpty);
            assert_eq!(c.category, Category::AppData);
            assert_eq!(c.harm, Harm::None);
            assert!(c.blockers.is_empty(), "{c:?}");
            let [evidence] = c.evidence.as_slice() else {
                panic!("one piece of evidence: {c:?}");
            };
            assert_eq!(evidence.kind, EvidenceKind::VendorContainer);
            assert_eq!(evidence.detail.get(PENDING_KEY), Some(PENDING_VALUE));
            assert!(
                evidence
                    .detail
                    .get("vendor")
                    .is_some_and(|v| v.eq_ignore_ascii_case("Mozilla")),
                "{evidence:?}"
            );
        }
        assert_eq!(
            listing(&found[0]),
            format!(r#"["profile_count_{HASH}.json","updates\\"]"#)
        );
        assert_eq!(listing(&found[1]), format!(r#"["{HASH}\\"]"#));
    }

    /// Another product's staging directory next to the app's is in the listing, so the plan cannot find
    /// `updates` (and with it the vendor folder) empty.
    #[test]
    fn listing_names_another_products_directory() {
        let fixture = machine()
            .file(&format!(r"{SHARED}\updates\{HASH}\update-config.json"), 1)
            .file(
                &format!(r"{SHARED}\updates\{OTHER_HASH}\update-config.json"),
                1,
            )
            .build();
        let found = scan(&firefox(fixture));
        assert_eq!(paths(&found), [SHARED, &format!(r"{SHARED}\updates")]);
        assert_eq!(
            listing(&found[1]),
            format!(r#"["{HASH}\\","{OTHER_HASH}\\"]"#)
        );
    }

    #[test]
    fn only_parents_of_token_dirs_are_offered() {
        let fixture = machine()
            // Nothing of the app below: not offered.
            .file(&format!(r"{SHARED}\logs\a.log"), 1)
            .dir(&format!(r"{SHARED}\empty"))
            // Deeper than FS-APPDATA looks for a token-named directory.
            .dir(&format!(r"{SHARED}\deep\er\{HASH}"))
            // A token-named directory directly in the vendor folder needs no parent.
            .dir(&format!(r"{ROAMING}\Mozilla\{HASH}"))
            // The product folder is FS-APPDATA's, whatever it holds.
            .dir(&format!(r"{ROAMING}\Mozilla\Firefox\{HASH}"))
            // A token-named file is no directory.
            .file(&format!(r"{ROAMING}\Mozilla\Pending\{HASH}"), 1)
            // Program Files is not an application-data base.
            .dir(&format!(r"C:\Program Files\Mozilla\updates\{HASH}"))
            .build();
        let found = scan(&firefox(fixture));
        assert_eq!(
            paths(&found),
            [
                &format!(r"{ROAMING}\Mozilla"),
                SHARED,
                r"C:\Program Files\Mozilla"
            ]
        );
    }

    #[test]
    fn unlistable_reparse_and_foreign_parents_are_not_offered() {
        // `updates` cannot be listed completely: the vendor folder is offered (its own listing is
        // complete, and names `updates`), `updates` is not.
        let fixture = machine()
            .dir(&format!(r"{SHARED}\updates\{HASH}"))
            .denied(&format!(r"{SHARED}\updates"))
            .build();
        assert_eq!(paths(&scan(&firefox(fixture))), [SHARED]);

        // A junction is never followed or offered.
        let fixture = machine()
            .reparse_dir(&format!(r"{SHARED}\updates"), 0xA000_0003)
            .build();
        assert_eq!(paths(&scan(&firefox(fixture))), [SHARED]);

        // A decorated name of another vendor, and a vendor name that only starts the same.
        let fixture = machine()
            .dir(&format!(
                r"C:\ProgramData\Contoso-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\{HASH}"
            ))
            .dir(r"C:\ProgramData\MozillaTools-1de4eec8-1241-4177-a864-e594e8d1fb38")
            .dir(r"C:\ProgramData\Mozilla-Backup")
            .build();
        assert!(scan(&firefox(fixture)).is_empty());

        // The app's own root inside the vendor folder is FS-INSTALLDIR's.
        let fixture = machine()
            .dir(&format!(r"{ROAMING}\Mozilla\Portable\{HASH}"))
            .build();
        let mut world = firefox(fixture);
        world.fp.roots[0].path = format!(r"{ROAMING}\Mozilla\Portable");
        assert_eq!(paths(&scan(&world)), [&format!(r"{ROAMING}\Mozilla")]);
    }

    #[test]
    fn baseline_and_mega_vendor_containers_are_never_offered() {
        let fixture = || {
            machine()
                .dir(&format!(r"{SHARED}\updates\{HASH}"))
                .dir(&format!(r"{ROAMING}\Mozilla"))
                .build()
        };
        // Clean Windows has the decorated folder: neither it nor anything below it is offered.
        let mut world = firefox(fixture());
        let mut text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t26340.9882\n");
        text.push_str(&format!("D\t{}\n", SHARED.replace('\\', "\\\\")));
        world.baseline = Some(
            purge_index::baseline::Baseline::from_bytes(text.as_bytes())
                .expect("the baseline parses"),
        );
        assert_eq!(paths(&scan(&world)), [&format!(r"{ROAMING}\Mozilla")]);
        // The same machine with an empty baseline offers all three.
        let mut world = firefox(fixture());
        world.baseline = Some(baseline(EDITION, &[]));
        assert_eq!(scan(&world).len(), 3);
        // A mega-vendor's containers are shared by too many products.
        let mut world = firefox(fixture());
        world.fp.identity.mega_vendor = true;
        assert!(scan(&world).is_empty());
    }

    #[test]
    fn folder_holding_another_app_is_blocked() {
        let fixture = machine()
            .file(&format!(r"{SHARED}\updates\{HASH}\a"), 1)
            .file(&format!(r"{SHARED}\updates\{OTHER_HASH}\b"), 1)
            .build();
        let mut world = firefox(fixture);
        world.other_apps = crate::framework::OtherApps::new(vec![crate::framework::OtherApp {
            name: "Mozilla Thunderbird".into(),
            roots: vec![format!(r"{SHARED}\updates\{OTHER_HASH}")],
            ..Default::default()
        }]);
        let found = scan(&world);
        assert_eq!(found.len(), 2);
        for c in &found {
            assert_eq!(
                c.blockers,
                [Blocker::ContainsOtherApp {
                    app: "Mozilla Thunderbird".into()
                }],
                "{c:?}"
            );
        }
    }
}
