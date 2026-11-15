//! REF-ANY (ENGINE_PLAN.md §5.6): any value in the reference-index scope whose name or data refers to
//! a harvested anchor. The catch-all behind the specific scanners.
//!
//! # Values
//!
//! The scanner runs the reference scan of `purge-index` over `HKLM\SOFTWARE`, the current control
//! set's `Services`, and the interactive user's `Software` and Classes hives, with the app's anchors
//! (roots, exe set, ProgIDs, CLSIDs, AUMIDs, tokens). Every value with a hit is read again and offered
//! at value level only: the whole value when it is about the app (its name refers to it, or its data
//! does and holds nothing else), or the matching entries of a list as segment edits.
//!
//! # `REG_MULTI_SZ`: lists and records
//!
//! A segment edit is right only for a value whose entries stand each for itself (the plan names the
//! `PATH` lists of REG-ENV and the filter lists of SYS-DRIVER, §5.6). Many `REG_MULTI_SZ` values are
//! records instead: fields that belong together by position (a shortcut, its target, its arguments).
//! Taking one field out of a record leaves a malformed value, so a `REG_MULTI_SZ` value is edited by
//! entry only when it has the shape of a list: every entry is a path and all entries are of one kind
//! (directories, or files of one extension). Anything else is one unit, like a string (`record`):
//!
//! - it is offered **whole** (a value delete), on the evidence of the entries that refer to the app;
//! - a value that clean Windows has under this name is not the app's to delete, whatever it says now
//!   (the app's record replaced an older one, and deleting the value removes something that was there
//!   before the install): it is not offered at all;
//! - without a baseline for exactly this Windows nothing shows that the value is newer than the app,
//!   and the entries that do not refer to the app are not attributed: `UnmatchedChildren` keeps the
//!   value offered but unchecked (values-only work, §5.7.1);
//! - the entries that do not refer to the app go with the value, so they must be nothing of their own:
//!   the value is also unchecked when one of them is the like of the app's entry (a second directory,
//!   a second `.exe`: a list after all, of mixed kinds) or names a path that is not proven absent.
//!
//! Evidence is Tier A when the harvest recorded the value (`InPreUninstallRefSnapshot`), when the
//! reference is dangling (`DanglingRef`) or points into an InstallRoot (`PointsIntoInstallRoot`), or
//! when a harvested token is part of the value's own name (`HarvestedToken`). A value that only
//! mentions a ProgID, CLSID or AUMID and was not in the snapshot gets no evidence and is not offered.
//! Hits in data that the source could not read in full are not used (`RefHit::cut_edge`,
//! `RefHit::data_complete`): the value is re-read and only complete data is tested.
//!
//! The two `Environment` keys are left out: there a reference is one entry of a list that every
//! program shares, and REG-ENV applies the stricter rules such an edit needs. Values a more specific
//! scanner also finds are emitted here all the same; `purge-plan` merges candidates on one target.
//!
//! # Keys
//!
//! A value never makes its key a candidate. A key is offered only on the fingerprint's own record of
//! it: a subtree baseline that the harvest attributed to the app in full. Such a key goes when it is a
//! proven owned skeleton (now value-free, see `skeleton`), or when everything in it now was already
//! there, attributed, at harvest (checked live against the baseline's value and subkey lists, the whole
//! subtree read) and the key itself carries Key-scope evidence: an Inno key-create record or a
//! harvested token in its name (under `SOFTWARE\Microsoft` only the record counts). Structural
//! containers are never offered.
//!
//! # One key, two names
//!
//! `HKLM\SOFTWARE\Classes` is one key for the 64-bit and the 32-bit view; only `CLSID`, `Interface`,
//! `DirectShow`, `Media Type` and `MediaFoundation` exist once per view. A path through the 32-bit node
//! to anything else (`HKLM\SOFTWARE\WOW6432Node\Classes\.txt\OpenWithProgids`) is a second name of the
//! shared key, and both the reference scan and the harvest's subtree baselines reach it under both
//! names. Such a value or key is offered once, under the canonical name
//! (`ScanCtx::shared_classes_alias`, which also checks that the source shows the two names to be one
//! key).
//!
//! # COM classes
//!
//! A value inside the key of a COM class the fingerprint does not attribute to the app is not offered
//! (`ScanCtx::in_unowned_com_class`): the class is another product's or a shared one, and the app
//! only pointed it at its own server.
//!
//! # Other apps and services
//!
//! A value whose name or data refers to another installed app as well gets `ReferencedByOtherApp`.
//! Values below the control set (`Services`) are emitted with the `CurrentControlSet` spelling and
//! `Category::System`: they are listed, never preselected.

use purge_guard::containers;
use purge_guard::prefix;
use purge_index::refscan::{self, RefScanOptions, Scope, default_prune};
use purge_model::{Action, Candidate, Category, SubtreeBaseline, Target};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};
use crate::reg_software::common::{self, Foreign};

mod record;

/// The scanner's catalog id.
pub const ID: &str = "REF-ANY";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"HKLM\SOFTWARE", None),
    RootSpec::reg(r"HKU\*\SOFTWARE", None),
    RootSpec::reg(r"HKLM\SYSTEM\CurrentControlSet\Services", None),
];

/// The keys the scanner reads single values from (entries of
/// `purge_guard::containers::VALUE_CONTAINERS`).
/// REF-ANY reads values everywhere in the reference-index scope; it declares the one container of that
/// scope that no more specific M1a scanner declares.
const VALUE_CONTAINERS: &[&str] = &[r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList"];

/// The REF-ANY scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefAny;

impl Scanner for RefAny {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let mut out = Vec::new();
        common::for_each_app(ctx, app, |ctx, app| scan_app(ctx, app, &mut out));
        common::dedupe(out)
    }
}

/// Whether `key` is one of the `Environment` keys REG-ENV owns.
fn is_environment(key: &str) -> bool {
    let lower = key.trim_end_matches(prefix::SEP).to_ascii_lowercase();
    let user = lower.starts_with(r"hku\") && prefix::depth(&lower) == 3;
    let machine = lower.starts_with(r"hklm\system\");
    (user && lower.ends_with(r"\environment"))
        || (machine && lower.ends_with(r"\control\session manager\environment"))
}

/// The reference-index scope without the `Environment` keys.
fn scope(ctx: &ScanCtx<'_>) -> Scope {
    let sids = common::user_sids(ctx);
    let roots: Vec<String> = match Scope::for_sids(ctx.reg, &sids) {
        Ok(scope) => scope.roots().to_vec(),
        // The source cannot name the current control set: scan what does not depend on it.
        Err(_) => std::iter::once(r"HKLM\SOFTWARE".to_owned())
            .chain(sids.iter().flat_map(|sid| {
                [
                    format!(r"HKU\{sid}\Software"),
                    format!(r"HKU\{sid}_Classes"),
                ]
            }))
            .collect(),
    };
    Scope::custom(
        roots.into_iter().filter(|root| !is_environment(root)),
        default_prune(),
    )
}

/// The rest of `key` below its control-set root (`HKLM\SYSTEM\ControlSet00N`), if it lies under one.
fn below_control_set(key: &str) -> Option<String> {
    let mut segments = prefix::segments(key);
    let (hive, system, set) = (segments.next()?, segments.next()?, segments.next()?);
    let digits = set
        .get(..10)
        .filter(|head| prefix::eq_ci(head, "ControlSet"))
        .and_then(|_| set.get(10..))?;
    let is_set = digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit());
    if !(prefix::eq_ci(hive, "HKLM") && prefix::eq_ci(system, "SYSTEM") && is_set) {
        return None;
    }
    Some(segments.collect::<Vec<_>>().join(r"\"))
}

/// Whether `key` lies under `SOFTWARE[\WOW6432Node]\Microsoft` of the machine or of a user hive.
fn under_microsoft(key: &str) -> bool {
    let mut segments = prefix::segments(key);
    let hive = segments.next().unwrap_or_default();
    if prefix::eq_ci(hive, "HKU") {
        segments.next();
    } else if !prefix::eq_ci(hive, "HKLM") {
        return false;
    }
    if !segments
        .next()
        .is_some_and(|s| prefix::eq_ci(s, "SOFTWARE"))
    {
        return false;
    }
    match segments.next() {
        Some(s) if prefix::eq_ci(s, "WOW6432Node") => segments
            .next()
            .is_some_and(|s| prefix::eq_ci(s, "Microsoft")),
        Some(s) => prefix::eq_ci(s, "Microsoft"),
        None => false,
    }
}

fn scan_app(ctx: &ScanCtx<'_>, app: &AppIdentityView, out: &mut Vec<Candidate>) {
    let scope = scope(ctx);
    if !app.anchors.is_empty() {
        let foreign = Foreign::new(ctx);
        let options = RefScanOptions {
            all_anchors: true,
            ..RefScanOptions::default()
        };
        let scan = refscan::scan(ctx.reg, &app.refs, &scope, &options, None);
        let mut last: Option<(&str, &str)> = None;
        for hit in &scan.hits {
            // The hits of one value follow each other; the value is read and offered once.
            let this = (hit.key.as_str(), hit.value_name.as_str());
            if last == Some(this) || is_environment(&hit.key) {
                continue;
            }
            last = Some(this);
            // A 32-bit-view spelling of a shared Classes key is the same key under a second name: the
            // value is offered once, under the canonical name (which the scan reaches as well).
            let canonical = ctx.shared_classes_alias(&hit.key);
            let hit_key = canonical.as_deref().unwrap_or(&hit.key);
            let Ok(data) = ctx.reg.value(hit_key, &hit.value_name) else {
                continue;
            };
            let value = purge_source::types::RegValue {
                name: hit.value_name.clone(),
                data,
            };
            // A value below the control set is part of a service's or driver's registration: system
            // integration, which the policy never preselects (a service is removed as a whole by its
            // own scanner, not by editing one value of it). It is named through `CurrentControlSet`,
            // the spelling a plan must use (see REG-ENV).
            let (key, category) = match below_control_set(hit_key) {
                Some(rest) => (
                    format!(r"HKLM\SYSTEM\CurrentControlSet\{rest}"),
                    Category::System,
                ),
                None => (hit_key.to_owned(), Category::Registration),
            };
            // A record-like REG_MULTI_SZ value is one unit; everything else is a whole value or a
            // list of entries.
            match record::record_refs(&app.refs, &value) {
                Some(found) => {
                    record::offer(ctx, app, &foreign, &key, &value, category, &found, out);
                }
                None => {
                    common::offer_value(ctx, app, &foreign, ID, &key, &value, category, out);
                }
            }
        }
    }
    for subtree in ctx.fp.subtrees.iter().filter(|s| s.fully_attributed) {
        if !scope.contains(&subtree.key) || containers::is_value_container(&subtree.key, ctx.guard)
        {
            continue;
        }
        // The harvest walks the 32-bit node of Classes too and records a shared key a second time
        // under that spelling. It is one key: it is offered once, on the record of its canonical
        // name.
        if let Some(canonical) = ctx.shared_classes_alias(&subtree.key) {
            let recorded = ctx
                .fp
                .subtrees
                .iter()
                .any(|s| s.fully_attributed && ctx.same_key(&s.key, &canonical));
            if recorded {
                continue;
            }
        }
        attributed_key(ctx, subtree, out);
    }
}

/// Offers the key of a fully attributed subtree baseline when it is a proven skeleton, or when it
/// still holds only what the harvest attributed and has Key-scope evidence of its own.
fn attributed_key(ctx: &ScanCtx<'_>, subtree: &SubtreeBaseline, out: &mut Vec<Candidate>) {
    let key = subtree.key.as_str();
    // A key inside a COM registration that is not the app's own is part of that registration, even
    // when all it ever held was a path the app wrote there.
    if ctx.in_unowned_com_class(key) || !ctx.reg.key_exists(key).is_present() {
        return;
    }
    let mut b = ctx.candidate(
        ID,
        Target::RegKey {
            path: key.to_owned(),
        },
        Action::DeleteKey,
        Category::Registration,
    );
    let walk = common::walk(ctx, key);
    let mut owned = b.proven_owned_skeleton();
    if !owned && covered(subtree, &walk) {
        owned = b.installer_manifest();
        let leaf = prefix::fold(prefix::leaf(key).unwrap_or_default());
        // Under `SOFTWARE\Microsoft` a key delete needs a manifest record or a proven skeleton
        // (§5.6): a token in the key's name is not enough there.
        let tokens = ctx.fp.tokens.iter().filter(|_| !under_microsoft(key));
        for token in tokens {
            if !token.token.is_empty() && leaf.contains(&prefix::fold(&token.token)) {
                owned |= b.harvested_token(&token.token);
            }
        }
    }
    if owned {
        b.child_count(walk.count());
        b.common_blockers();
        out.push(b.build());
    }
}

/// Whether everything the walk found was in the subtree at harvest, and the walk read everything.
fn covered(subtree: &SubtreeBaseline, walk: &common::KeyWalk) -> bool {
    let relative = |key: &str| prefix::strip_prefix(key, &subtree.key).map(str::to_owned);
    walk.complete
        && walk.values.iter().all(|(at, value)| {
            relative(at).is_some_and(|sub| {
                subtree.values.iter().any(|v| {
                    prefix::is_same(&v.subkey, &sub) && prefix::eq_ci(&v.name, &value.name)
                })
            })
        })
        && walk.subkeys.iter().all(|at| {
            relative(at).is_some_and(|sub| subtree.subkeys.iter().any(|s| prefix::is_same(s, &sub)))
        })
}
