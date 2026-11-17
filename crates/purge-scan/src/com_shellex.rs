//! Scanner COM-SHELLEX (ENGINE_PLAN.md §5.6; M1b package M1B-S-SHELLEX): shell-extension registrations
//! that name one of the app's COM classes: context-menu, property-sheet, drag-and-drop, copy-hook and
//! column handlers, icon and drop handlers, the handlers Windows keys by interface id (thumbnail,
//! preview, property handlers of a type), icon overlays, browser helper objects, and the entries of the
//! shell's approval lists.
//!
//! # What is looked at
//!
//! Nothing is walked. The scanner reads:
//!
//! - the hits of the one reference walk of the pipeline ([`ScanCtx::ext`]) that are values of the places
//!   below, for the app's CLSIDs (`fp.anchors.clsids`, the classes the harvest found served from the
//!   app's files);
//! - one `subkeys()` listing of each fixed handler list (the five lists below of the eight shell objects
//!   [`SHELL_OBJECTS`], `ShellIconOverlayIdentifiers` and `Browser Helper Objects`), to find handler keys
//!   whose **name** is one of the app's CLSIDs (their default value need not name anything);
//! - per handler key found, its values and its subkey names; per value found, the value itself;
//! - the class keys themselves, through COM-CLASS's judgement ([`crate::com_class::ClassCache`]), read
//!   once per class and view.
//!
//! The places, in the machine's Classes and in the Classes of each user the reference walk covered:
//!
//! - `<object>\shellex\{ContextMenuHandlers, PropertySheetHandlers, DragDropHandlers, CopyHookHandlers,
//!   ColumnHandlers}\<handler>` and `<object>\shellex\{IconHandler, DropHandler, {IID}}` for `<object>`
//!   one of [`SHELL_OBJECTS`], one of the app's ProgIDs or a file extension;
//!
//! and below `...\Microsoft\Windows\CurrentVersion` of `HKLM\SOFTWARE`, `HKLM\SOFTWARE\WOW6432Node` and
//! each walked user's `Software`:
//!
//! - `Explorer\ShellIconOverlayIdentifiers\<name>` and `Explorer\Browser Helper Objects\{CLSID}` (keys);
//! - `Shell Extensions\Approved`, `Explorer\ShellExecuteHooks` and `Explorer\SharedTaskScheduler` (a
//!   value named `{CLSID}`), and in a user's hive `Shell Extensions\Cached` (a value whose name is
//!   `{CLSID}` followed by nothing or by a blank and more). These four keys are lists every product
//!   writes to: only a single value is ever offered, never the key.
//!
//! The 32-bit spelling of the Classes (`...\Classes\WOW6432Node\<object>`) is skipped: the shell objects,
//! ProgIDs and extensions are not redirected, so that spelling names the same key.
//!
//! # Which handler
//!
//! A handler key stands for the class its default value names (a `{GUID}`); when the default is not a
//! GUID, for the class its own name is (the shell's reading). It is the app's when that class is one of
//! the app's CLSIDs. A handler whose default names another class is that class's, whatever the key is
//! called.
//!
//! The key is offered whole (`DeleteKey`) only when it holds nothing but the default value (and, below
//! `Browser Helper Objects`, the `NoExplorer` switch that belongs to the registration) and has no
//! subkey. Otherwise only the default value is offered (`DeleteValue`), and only when the default itself
//! names the class: a key named by the class whose default is text, next to other values or subkeys, is
//! not offered at all. The handler lists themselves and the `shellex` keys are never candidates.
//!
//! # The class, view by view
//!
//! A handler is used in the registry views its place serves: the 64-bit places in the 64-bit view, the
//! `WOW6432Node` places in the 32-bit view, the Classes and a user's `Software` in both. In each such
//! view, of the machine and of every loaded user, the class is judged as COM-CLASS judges it:
//!
//! - registered to an existing file that is not the app's, in **any** view: another product took the
//!   class over. Nothing is offered.
//! - a view that cannot be read, that Windows has, whose server is not one file, or whose class COM-CLASS
//!   lists with a hard blocker (another class emulating it, a shared proxy...): nothing is offered.
//! - in another user's hive that the reference walk did not cover, any trace of the class: nothing is
//!   offered (who refers to it there is not known).
//! - **dangling**: in every view the class is absent or is the app's with every server missing and the
//!   full dangling rule proven (COM-CLASS rule (a)), at least one such: `ComKeyOwnership` (a key) or
//!   `ChainedRef` to the class (a value), plus the class's `DanglingRef` evidence: Safe when the rest
//!   holds.
//! - **gone**: the class key is absent in every view of the machine and of every loaded user:
//!   `ComKeyOwnership` and `ChainedRef` (a key: Safe when the rest holds) or `ChainedRef` (a value; Safe
//!   only with the harvest's record of the value as well, `InPreUninstallRefSnapshot`).
//! - otherwise (a server of the app still there, a server missing without the full proof, the class
//!   only in a view the place does not serve): the same evidence at Tier B at most: Likely.
//!
//! `ComKeyOwnership` on a handler key is Tier A only with a baseline of exactly this Windows that does
//! not have the key; a value is Tier A only with such a baseline loaded. A key or value Windows has is
//! never offered: a Windows handler the app re-pointed at its own class stays as it is.
//!
//! # Missing data
//!
//! There is no scan-warning channel for scanners yet: a place, key, value or class that cannot be read
//! (`AccessDenied`, `NotCaptured`, data not read in full) makes no candidate, silently. Without the
//! reference walk the scanner offers nothing.

use std::collections::HashSet;

use purge_guard::prefix;
use purge_index::refscan::RefHit;
use purge_model::{
    Action, AnchorKind, AnchorRef, Blocker, Candidate, Category, Evidence, EvidenceKind, Facts,
    SourceTrust, Target, Tier,
};
use purge_source::types::{RegData, RegValue};

use crate::cls_progid::classes;
use crate::com_class::{
    ClassCache, ClassState, HKLM_CLASSES, Offer, Place, anchor_ids, bare, classes_roots,
    com_key_ownership, is_anchor, is_braced_guid, proven_not_windows, shared_iids, split_classes,
    walk_hits, walked_user_sids,
};
use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner, anchor_trust, weakest};

/// The scanner's catalog id.
pub const ID: &str = "COM-SHELLEX";

/// The locations the scanner reads: the `shellex` keys of every Classes key (shell objects, ProgIDs,
/// extensions) down to the handler keys, the class keys COM-CLASS reads for the classes named, the
/// Explorer extension lists and the shell's approval lists.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"HKCR\*\shellex", Some(2)),
    RootSpec::reg(r"HKCR\Directory\Background\shellex", Some(2)),
    RootSpec::reg(r"HKCR\CLSID", Some(3)),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
        Some(1),
    ),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        Some(1),
    ),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        Some(0),
    ),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        Some(0),
    ),
    RootSpec::reg(
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        Some(0),
    ),
    RootSpec::reg(
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached",
        Some(0),
    ),
];

/// The value containers read here that the guard lists ([`purge_guard::containers`]). `Cached`,
/// `ShellExecuteHooks` and `SharedTaskScheduler` are value containers too by C-GUARD, but the guard's
/// tables do not list them yet (its deny-list keeps the keys themselves); they are left out so that the
/// catalog's check of this list against the guard's table holds. Only single values are offered from
/// any of the four.
const VALUE_CONTAINERS: &[&str] =
    &[r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"];

/// The shell objects whose handler lists are also listed by name: every file (`*`), the file-system
/// objects, folders and their background, drives, shortcuts, libraries.
pub const SHELL_OBJECTS: &[&str] = &[
    "*",
    "AllFilesystemObjects",
    "Directory",
    r"Directory\Background",
    "Drive",
    "Folder",
    "lnkfile",
    "LibraryFolder",
];

/// The handler lists below `shellex`: each holds one named key per handler.
const HANDLER_LISTS: &[&str] = &[
    "ContextMenuHandlers",
    "PropertySheetHandlers",
    "DragDropHandlers",
    "CopyHookHandlers",
    "ColumnHandlers",
];

/// The handler keys below `shellex` that are one handler each (besides those named by an interface id).
const SINGLE_HANDLERS: &[&str] = &["IconHandler", "DropHandler"];

/// `...\Microsoft\Windows\CurrentVersion` below a `Software` root.
const CURRENT_VERSION: [&str; 3] = ["Microsoft", "Windows", "CurrentVersion"];

/// The Explorer lists of named handler keys, below `CurrentVersion`.
const OVERLAYS: [&str; 2] = ["Explorer", "ShellIconOverlayIdentifiers"];
const BHOS: [&str; 2] = ["Explorer", "Browser Helper Objects"];

/// The values a `Browser Helper Objects\{CLSID}` key holds as part of the registration.
const BHO_VALUES: &[&str] = &["NoExplorer"];

/// The COM-SHELLEX scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComShellex;

impl Scanner for ComShellex {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn value_containers(&self) -> &[&'static str] {
        VALUE_CONTAINERS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        // Without the walk no handler that names a class by its default value can be found, and
        // without the KB no class can be judged: nothing is offered (no warning channel yet).
        let Some(hits) = walk_hits(ctx) else {
            return Vec::new();
        };
        let Some(kb) = shared_iids() else {
            return Vec::new();
        };
        if anchor_ids(&ctx.fp.anchors.clsids).is_empty() {
            return Vec::new();
        }
        let mut found = Found::default();
        let classes_roots = classes_roots(ctx);
        let software = software_roots(ctx);
        for hit in hits {
            found.take_hit(ctx, hit, &classes_roots, &software);
        }
        found.take_lists(ctx, &classes_roots, &software);

        let mut classes = ClassCache::new(hits, kb);
        let mut out = Vec::new();
        for handler in &found.handlers {
            out.extend(handler_candidate(ctx, &mut classes, handler));
        }
        for value in &found.values {
            out.extend(value_candidate(ctx, &mut classes, value));
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------------------
// Places
// ---------------------------------------------------------------------------------------------------------

/// The registry views a place serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bits {
    /// Both (the Classes, a user's `Software`).
    Both,
    /// The 64-bit view only (`HKLM\SOFTWARE`).
    K64,
    /// The 32-bit view only (`HKLM\SOFTWARE\WOW6432Node`).
    K32,
}

impl Bits {
    fn serves(self, place: &Place) -> bool {
        match self {
            Bits::Both => true,
            Bits::K64 => !place.wow,
            Bits::K32 => place.wow,
        }
    }
}

/// A `Software` root: `HKLM\SOFTWARE`, `HKLM\SOFTWARE\WOW6432Node` or `HKU\<SID>\Software`.
#[derive(Debug, Clone)]
struct SoftwareRoot {
    root: String,
    bits: Bits,
    user: bool,
}

impl SoftwareRoot {
    /// `<root>\Microsoft\Windows\CurrentVersion\<tail>`.
    fn key(&self, tail: &[&str]) -> String {
        let mut out = self.root.clone();
        for seg in CURRENT_VERSION.iter().chain(tail) {
            out.push(prefix::SEP);
            out.push_str(seg);
        }
        out
    }

    /// The segments of `key` below `<root>\Microsoft\Windows\CurrentVersion`; `None` when it is not
    /// below.
    fn below<'k>(&self, key: &'k str) -> Option<Vec<&'k str>> {
        let mut segs = prefix::segments(key);
        for want in prefix::segments(&self.root).chain(CURRENT_VERSION) {
            if !prefix::eq_ci(segs.next()?, want) {
                return None;
            }
        }
        Some(segs.collect())
    }
}

/// The `Software` roots: the machine's in both views and each walked user's.
fn software_roots(ctx: &ScanCtx<'_>) -> Vec<SoftwareRoot> {
    let mut out = vec![
        SoftwareRoot {
            root: r"HKLM\SOFTWARE".to_owned(),
            bits: Bits::K64,
            user: false,
        },
        SoftwareRoot {
            root: r"HKLM\SOFTWARE\WOW6432Node".to_owned(),
            bits: Bits::K32,
            user: false,
        },
    ];
    out.extend(walked_user_sids(ctx).into_iter().map(|sid| SoftwareRoot {
        root: format!(r"HKU\{sid}\Software"),
        bits: Bits::Both,
        user: true,
    }));
    out
}

/// Whether `object` (the segments between the Classes root and `shellex`) is a key whose handlers are
/// looked at: a shell object, one of the app's ProgIDs, or a file extension.
fn is_handler_owner(ctx: &ScanCtx<'_>, object: &[&str]) -> bool {
    let joined = object.join(r"\");
    if SHELL_OBJECTS.iter().any(|o| prefix::eq_ci(o, &joined)) {
        return true;
    }
    let [single] = object else {
        return false;
    };
    (single.starts_with('.') && single.len() > 1)
        || ctx
            .fp
            .anchors
            .progids
            .iter()
            .any(|p| prefix::eq_ci(p, single))
}

/// A handler key found.
#[derive(Debug, Clone)]
struct HandlerKey {
    /// The key.
    key: String,
    /// Its name (the last segment).
    name: String,
    /// The views it serves.
    bits: Bits,
    /// Values the key may hold besides its default value as part of the registration.
    allowed: &'static [&'static str],
}

/// What a listed value is named after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    /// The name is the `{CLSID}`.
    Named,
    /// The name is the `{CLSID}`, then nothing or a blank and more (`Shell Extensions\Cached`).
    Prefixed,
}

/// A value of a list found.
#[derive(Debug, Clone)]
struct ListValue {
    key: String,
    name: String,
    clsid: String,
    bits: Bits,
}

/// Everything found, each once.
#[derive(Default)]
struct Found {
    handlers: Vec<HandlerKey>,
    values: Vec<ListValue>,
    seen: HashSet<String>,
}

impl Found {
    fn add_handler(&mut self, handler: HandlerKey) {
        if self
            .seen
            .insert(format!("k|{}", prefix::fold(&handler.key)))
        {
            self.handlers.push(handler);
        }
    }

    fn add_value(&mut self, value: ListValue) {
        let id = format!(
            "v|{}|{}",
            prefix::fold(&value.key),
            prefix::fold(&value.name)
        );
        if self.seen.insert(id) {
            self.values.push(value);
        }
    }

    /// Takes what a hit of the walk shows: a handler key whose default value names an id of the app, or
    /// a value of a list named after one.
    fn take_hit(
        &mut self,
        ctx: &ScanCtx<'_>,
        hit: &RefHit,
        classes_roots: &[String],
        software: &[SoftwareRoot],
    ) {
        if !matches!(hit.anchor.kind, AnchorKind::Clsid | AnchorKind::Token) {
            return;
        }
        if let Some(at) = split_classes(&hit.key) {
            // The 32-bit spelling of a key that is not redirected names the shared key; the walk
            // reports it under its own spelling too.
            if at.place.wow
                || !hit.value_name.is_empty()
                || !classes_roots
                    .iter()
                    .any(|r| prefix::eq_ci(r, &at.place.root))
            {
                return;
            }
            if let Some(handler) = classes_handler(ctx, &at.place.root, &at.rest) {
                self.add_handler(handler);
            }
            return;
        }
        for root in software {
            let Some(tail) = root.below(&hit.key) else {
                continue;
            };
            match tail.as_slice() {
                [a, b, name] if prefix::eq_ci(a, OVERLAYS[0]) && prefix::eq_ci(b, OVERLAYS[1]) => {
                    if hit.value_name.is_empty() {
                        self.add_handler(HandlerKey {
                            key: root.key(&[*a, *b, *name]),
                            name: (*name).to_owned(),
                            bits: root.bits,
                            allowed: &[],
                        });
                    }
                }
                [a, b] => {
                    let kind =
                        if prefix::eq_ci(a, "Shell Extensions") && prefix::eq_ci(b, "Approved") {
                            Some(ValueKind::Named)
                        } else if root.user
                            && prefix::eq_ci(a, "Shell Extensions")
                            && prefix::eq_ci(b, "Cached")
                        {
                            Some(ValueKind::Prefixed)
                        } else if prefix::eq_ci(a, "Explorer")
                            && (prefix::eq_ci(b, "ShellExecuteHooks")
                                || prefix::eq_ci(b, "SharedTaskScheduler"))
                        {
                            Some(ValueKind::Named)
                        } else {
                            None
                        };
                    if let Some(kind) = kind
                        && let Some(clsid) = owned_value_name(ctx, &hit.value_name, kind)
                    {
                        self.add_value(ListValue {
                            key: root.key(&[*a, *b]),
                            name: hit.value_name.clone(),
                            clsid,
                            bits: root.bits,
                        });
                    }
                }
                _ => {}
            }
            return;
        }
    }

    /// Lists each fixed handler list once, for handler keys named by one of the app's CLSIDs. A list
    /// that cannot be read is skipped (no warning channel yet).
    fn take_lists(
        &mut self,
        ctx: &ScanCtx<'_>,
        classes_roots: &[String],
        software: &[SoftwareRoot],
    ) {
        let mut lists: Vec<(String, Bits, &'static [&'static str])> = Vec::new();
        for root in classes_roots {
            for object in SHELL_OBJECTS {
                for list in HANDLER_LISTS {
                    lists.push((format!(r"{root}\{object}\shellex\{list}"), Bits::Both, &[]));
                }
            }
        }
        for root in software {
            lists.push((root.key(&OVERLAYS), root.bits, &[]));
            lists.push((root.key(&BHOS), root.bits, BHO_VALUES));
        }
        for (list, bits, allowed) in lists {
            let Ok(names) = ctx.reg.subkeys(&list) else {
                continue;
            };
            for name in names {
                if is_braced_guid(&name) && is_anchor(&ctx.fp.anchors.clsids, &name) {
                    self.add_handler(HandlerKey {
                        key: format!(r"{list}\{name}"),
                        name,
                        bits,
                        allowed,
                    });
                }
            }
        }
    }
}

/// The handler key a hit at `rest` (below the Classes root `root`) is the default value of, if it is
/// one of the places.
fn classes_handler(ctx: &ScanCtx<'_>, root: &str, rest: &[&str]) -> Option<HandlerKey> {
    let at = rest.iter().position(|s| prefix::eq_ci(s, "shellex"))?;
    if at == 0 || !is_handler_owner(ctx, &rest[..at]) {
        return None;
    }
    let below = &rest[at + 1..];
    let handler = match below {
        [list, _] if HANDLER_LISTS.iter().any(|l| prefix::eq_ci(l, list)) => true,
        [single]
            if SINGLE_HANDLERS.iter().any(|s| prefix::eq_ci(s, single))
                || is_braced_guid(single) =>
        {
            true
        }
        _ => false,
    };
    if !handler {
        return None;
    }
    let name = (*rest.last()?).to_owned();
    Some(HandlerKey {
        key: format!(r"{root}\{}", rest.join(r"\")),
        name,
        bits: Bits::Both,
        allowed: &[],
    })
}

/// The app's CLSID a value of a list is named after, braced as in the anchors; `None` when the name
/// is not of the `kind`'s form or the id is not the app's.
fn owned_value_name(ctx: &ScanCtx<'_>, name: &str, kind: ValueKind) -> Option<String> {
    let id = match kind {
        ValueKind::Named => name,
        ValueKind::Prefixed => {
            let head = name.get(..38)?;
            let rest = &name[38..];
            if !(rest.is_empty() || rest.starts_with(char::is_whitespace)) {
                return None;
            }
            head
        }
    };
    (is_braced_guid(id) && is_anchor(&ctx.fp.anchors.clsids, id)).then(|| id.to_owned())
}

// ---------------------------------------------------------------------------------------------------------
// The class
// ---------------------------------------------------------------------------------------------------------

/// How the class a registration names stands, over the views the registration serves.
#[derive(Debug, Clone)]
enum Standing {
    /// Absent or proven dangling in every view served, dangling in at least one.
    Dangling {
        /// The tier of the class's own `ComKeyOwnership`, the weakest over the dangling views.
        tier: Tier,
        /// The trust of its servers' roots.
        trust: SourceTrust,
        /// The `DanglingRef` evidence of every dangling view.
        dangling: Vec<Evidence>,
        /// A class key, for `ChainedRef`.
        class_key: String,
    },
    /// The class key is absent in every view of the machine and every loaded user.
    Gone {
        /// Tier A when a baseline of this Windows shows the class is not Windows' own.
        tier: Tier,
        /// The trust of the anchor.
        trust: SourceTrust,
    },
    /// The class is the app's but not shown gone: Likely at most, for the reason given.
    Unproven {
        why: &'static str,
        trust: SourceTrust,
        class_key: Option<String>,
    },
}

/// Every place a class may be registered: both views of the machine's Classes and of every loaded
/// user's, with whether the reference walk covered that user's hive.
fn every_class_place(ctx: &ScanCtx<'_>) -> Vec<(Place, bool)> {
    let walked = walked_user_sids(ctx);
    let mut roots: Vec<(String, bool)> = vec![(HKLM_CLASSES.to_owned(), true)];
    for sid in classes::user_sids(ctx) {
        let covered = walked.iter().any(|w| prefix::eq_ci(w, &sid));
        roots.push((format!(r"HKU\{sid}_Classes"), covered));
    }
    roots
        .into_iter()
        .flat_map(|(root, covered)| {
            [false, true].map(|wow| {
                (
                    Place {
                        root: root.clone(),
                        wow,
                    },
                    covered,
                )
            })
        })
        .collect()
}

/// Judges the class `clsid` (one of the app's) for a registration serving `bits`. `None`: nothing may
/// be offered.
fn standing(
    ctx: &ScanCtx<'_>,
    classes: &mut ClassCache<'_>,
    clsid: &str,
    bits: Bits,
) -> Option<Standing> {
    let places = every_class_place(ctx);
    // Another product took the class over in some view: never.
    for (place, _) in &places {
        if matches!(classes.get(ctx, place, clsid).state, ClassState::Foreign(_)) {
            return None;
        }
    }
    let mut all_absent = true;
    let mut served_present = false;
    let mut unproven: Option<&'static str> = None;
    let mut dangling: Vec<Evidence> = Vec::new();
    let mut tier = Tier::A;
    let mut trust = SourceTrust::AdminOnly;
    let mut class_key: Option<String> = None;
    for (place, covered) in &places {
        let view = classes.get(ctx, place, clsid);
        if view.state == ClassState::Absent {
            continue;
        }
        all_absent = false;
        // A hive the walk did not cover: who refers to the class there is unknown.
        if !covered {
            return None;
        }
        if !bits.serves(place) {
            continue;
        }
        served_present = true;
        let ClassState::Own(_) = view.state else {
            // Unreadable, Windows' own, not one file of the app, a shared proxy.
            return None;
        };
        // COM-CLASS lists the class with a hard blocker (another class emulates it, a shared
        // interface uses it as proxy, it predates the install...): it is not the app's to drop.
        let offer = view.offer?;
        trust = weakest(trust, view.trust);
        class_key.get_or_insert_with(|| view.key.clone());
        let own_tier = view
            .candidate
            .as_ref()
            .and_then(|c| {
                c.evidence
                    .iter()
                    .find(|e| e.kind == EvidenceKind::ComKeyOwnership)
            })
            .map(|e| e.tier);
        match (offer, own_tier) {
            (Offer::Dangling, Some(own)) if !view.dangling.is_empty() => {
                tier = tier.at_most(own);
                dangling.extend(view.dangling.iter().cloned());
            }
            (Offer::Dangling, _) => {
                unproven.get_or_insert("the class's server is missing, but not proven gone");
            }
            (Offer::Present, _) => {
                unproven.get_or_insert("the class's server is still there");
            }
        }
    }
    if all_absent {
        let machine_key = |wow| {
            Place {
                root: HKLM_CLASSES.to_owned(),
                wow,
            }
            .key("CLSID", clsid)
        };
        let proven = proven_not_windows(ctx, &machine_key(false))
            && proven_not_windows(ctx, &machine_key(true));
        return Some(Standing::Gone {
            tier: if proven { Tier::A } else { Tier::B },
            trust: anchor_trust(
                ctx.fp,
                &AnchorRef {
                    kind: AnchorKind::Clsid,
                    text: clsid.to_owned(),
                },
            ),
        });
    }
    if !served_present {
        return Some(Standing::Unproven {
            why: "the class is registered only in a view this place does not serve",
            trust,
            class_key,
        });
    }
    match (unproven, class_key) {
        (None, Some(class_key)) => Some(Standing::Dangling {
            tier,
            trust,
            dangling,
            class_key,
        }),
        (why, class_key) => Some(Standing::Unproven {
            why: why.unwrap_or("the class is not proven gone"),
            trust,
            class_key,
        }),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------------------------------------

/// The trimmed string of `data`, `None` when it is no complete string or is empty.
fn string_of(data: &RegData) -> Option<String> {
    if !data.is_complete() {
        return None;
    }
    data.string()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The candidate for a handler key: the key, its default value, or nothing.
fn handler_candidate(
    ctx: &ScanCtx<'_>,
    classes: &mut ClassCache<'_>,
    handler: &HandlerKey,
) -> Option<Candidate> {
    let key = &handler.key;
    // A key or a listing that cannot be read: no candidate (no warning channel yet).
    let values: Vec<RegValue> = ctx.reg.values(key).ok()?;
    let subkeys = ctx.reg.subkeys(key).ok()?;
    let default = values.iter().find(|v| v.name.is_empty());
    // A default value that is there but not read in full says nothing about which class it names.
    if default.is_some_and(|v| !v.data.is_complete()) {
        return None;
    }
    let default_text = default.and_then(|v| string_of(&v.data));
    let default_guid = default_text.as_deref().filter(|t| is_braced_guid(t));
    // The shell's reading: the default when it is a GUID, else the key's name.
    let clsid = match default_guid {
        Some(guid) => guid.to_owned(),
        None if is_braced_guid(&handler.name) => handler.name.clone(),
        None => return None,
    };
    if !is_anchor(&ctx.fp.anchors.clsids, &clsid) {
        return None;
    }
    let clsid = format!("{{{}}}", bare(&clsid));
    let whole = subkeys.is_empty()
        && values.iter().all(|v| {
            v.name.is_empty() || handler.allowed.iter().any(|a| prefix::eq_ci(a, &v.name))
        });
    let target = if whole {
        Target::RegKey { path: key.clone() }
    } else if default_guid.is_some() {
        Target::RegValue {
            path: key.clone(),
            name: String::new(),
        }
    } else {
        // Named by the class, with text as its default next to other content: deleting the default
        // would not unregister it, and the key holds what is not shown to be the app's.
        return None;
    };
    // Windows has it: a Windows handler the app re-pointed stays as it is.
    if ctx.in_baseline(&Target::RegKey { path: key.clone() }) || ctx.in_baseline(&target) {
        return None;
    }
    let standing = standing(ctx, classes, &clsid, handler.bits)?;
    Some(build(ctx, target, &clsid, &standing))
}

/// The candidate for a value of a list, or nothing.
fn value_candidate(
    ctx: &ScanCtx<'_>,
    classes: &mut ClassCache<'_>,
    value: &ListValue,
) -> Option<Candidate> {
    // The value as it is now; gone or unreadable: no candidate.
    ctx.reg.value(&value.key, &value.name).ok()?;
    let target = Target::RegValue {
        path: value.key.clone(),
        name: value.name.clone(),
    };
    if ctx.in_baseline(&target) {
        return None;
    }
    let standing = standing(ctx, classes, &value.clsid, value.bits)?;
    Some(build(ctx, target, &value.clsid, &standing))
}

/// Builds the candidate on `target` (a handler key, or a value) for the app's class `clsid`.
fn build(ctx: &ScanCtx<'_>, target: Target, clsid: &str, standing: &Standing) -> Candidate {
    let is_key = matches!(target, Target::RegKey { .. });
    let action = if is_key {
        Action::DeleteKey
    } else {
        Action::DeleteValue
    };
    let key = match &target {
        Target::RegKey { path } | Target::RegValue { path, .. } => path.clone(),
        _ => String::new(),
    };
    let mut b = ctx.candidate(ID, target, action, Category::ShellCom);
    let (tier, trust, chain) = match standing {
        Standing::Dangling {
            tier,
            trust,
            class_key,
            ..
        } => (*tier, *trust, class_key.clone()),
        Standing::Gone { tier, trust } => (*tier, *trust, clsid.to_owned()),
        Standing::Unproven {
            trust, class_key, ..
        } => (
            Tier::B,
            *trust,
            class_key.clone().unwrap_or_else(|| clsid.to_owned()),
        ),
    };
    let mut key_tier = Tier::A;
    if is_key {
        let ownership =
            com_key_ownership(ctx, &key, trust, Ok(()), Facts::new().with("clsid", clsid));
        key_tier = ownership.as_ref().map_or(Tier::B, |e| e.tier);
        b.evidence_also(ownership);
    }
    b.chained_ref(tier, &chain);
    match standing {
        Standing::Dangling { dangling, .. } => b.evidence_also(dangling.iter().cloned()),
        Standing::Gone { .. } => {
            // The harvest's record of this very value, the corroboration a value needs when no
            // server path is left to prove dangling.
            if !is_key {
                b.in_ref_snapshot();
            }
        }
        Standing::Unproven { why, .. } => {
            b.cap_at_tier_b(why);
        }
    }
    if is_key && key_tier != Tier::A {
        b.cap_at_tier_b("the handler key is not proven not Windows' own");
    }
    if !is_key && classes::matching_baseline(ctx).is_none() {
        b.cap_at_tier_b("no baseline of this Windows");
    }
    if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::Clsid, clsid) {
        b.blocker(blocker);
    }
    if is_key && ctx.predates_install(&key) {
        b.blocker(Blocker::ExistedBeforeInstall);
    }
    b.common_blockers();
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_are_well_formed() {
        for root in ROOTS {
            assert!(root.is_well_formed(), "{root:?}");
        }
    }

    #[test]
    fn value_containers_lie_under_the_roots() {
        for container in VALUE_CONTAINERS {
            assert!(
                ROOTS
                    .iter()
                    .any(|r| r.pattern.eq_ignore_ascii_case(container)),
                "{container}"
            );
            assert!(
                purge_guard::containers::M1B_VALUE_CONTAINERS.contains(container),
                "{container}"
            );
        }
    }

    #[test]
    fn fixed_lists_fit_the_budget() {
        // One subkeys() call per fixed list: at most 60 per registry view.
        assert!(SHELL_OBJECTS.len() * HANDLER_LISTS.len() <= 60);
    }

    #[test]
    fn software_root_below() {
        let root = SoftwareRoot {
            root: r"HKLM\SOFTWARE".into(),
            bits: Bits::K64,
            user: false,
        };
        let key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";
        assert_eq!(root.below(key), Some(vec!["Shell Extensions", "Approved"]));
        assert_eq!(
            root.below(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\X"),
            None
        );
        assert_eq!(
            root.key(&["Explorer", "ShellExecuteHooks"]),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
        );
    }
}
