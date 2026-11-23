//! Scanner COM-CLASS (ENGINE_PLAN.md §5.6, §5.7.2; M1b package M1B-S-COM): the app's own `CLSID`,
//! `AppID` and `TypeLib` registrations.
//!
//! # What is looked at
//!
//! Nothing is walked. The scanner starts from the ids the harvest recorded as the app's
//! (`fp.anchors.clsids`, `appids`, `typelibs`: classes whose server lay in the app's files before the
//! uninstall, the AppIDs those classes named, type libraries whose files were the app's, and the rows
//! of the app's own MSI `Class`, `TypeLib` and `AppId` tables) and opens exactly the keys those ids name
//! in every registry view ([`Place`]):
//!
//! - `CLSID\{x}` in `HKLM\SOFTWARE\Classes`, `HKLM\SOFTWARE\Classes\WOW6432Node` and, for every user
//!   hive the shared reference walk covered, `HKU\<SID>_Classes` and `HKU\<SID>_Classes\WOW6432Node`;
//! - `AppID\{x}`, `AppID\<exe name>` and `TypeLib\{x}` in the machine's Classes and each such user's
//!   (these are not redirected by WOW64, [`crate::framework::CLASSES_REDIRECTED`]).
//!
//! Who else refers to a class (another class's `TreatAs`, an `Interface` naming it as its proxy, a class
//! naming an AppID) comes from the hits of the one reference walk the pipeline runs
//! ([`ScanCtx::ref_hits_under`]); without that walk the scanner offers nothing, because "no other
//! referrer" cannot be shown.
//!
//! # Targets
//!
//! Every target is spelled through the physical key: the 32-bit classes as
//! `HKLM\SOFTWARE\Classes\WOW6432Node\...` (never the `HKLM\SOFTWARE\WOW6432Node\Classes` link), a user's
//! classes as `HKU\<SID>_Classes\...` (the hive `HKU\<SID>\Software\Classes` links to), never `HKCR`.
//!
//! # A class, per view
//!
//! The server is the default value of `InprocServer32` (a plain path), of `LocalServer32` (a command
//! line, resolved by `purge_index::sysobj::resolve_program`: an interpreter or host such as `rundll32`
//! is never the app's program) and, when neither exists, of `InprocHandler32`. A .NET class served by
//! `mscoree.dll` is served by the file its `CodeBase` names (`file:///` form decoded); without one it is
//! in the global assembly cache and is never offered.
//!
//! - (a) every server is a file of the app (inside an InstallRoot, or one of its exe or outside-root
//!   files) and is missing: `DeleteKey` with `ComKeyOwnership` and, when the full dangling rule holds
//!   for every server (`ScanCtx::dangling`), `DanglingRef` about the server value: Safe.
//! - (b) the same with a server present: `ComKeyOwnership` only: Likely.
//! - (c) a server is an existing file outside the app: another product registered the class after the
//!   app. Listed with `ReferencedByOtherApp`, so the user sees why it stays.
//! - (d) a server outside the app that is missing or cannot be told to be one file, no server, a .NET
//!   class without `CodeBase`, a key in the baseline, a key that cannot be read: nothing.
//!
//! `ComKeyOwnership` is Tier A only with a baseline of exactly this Windows that does not have the key
//! and when every subkey is one COM defines for a class ([`STANDARD_CLASS_SUBKEYS`]); otherwise it is
//! recorded at Tier B and says why.
//!
//! A class named by another class's `TreatAs`/`AutoTreatAs`, or as the proxy of an interface listed in
//! `kb/shared-iids.json`, is protected; a class in the KB's `shared_proxy_clsids` is never a candidate.
//!
//! # AppIDs and type libraries
//!
//! - `AppID\{x}`: only when the walk can see the id (it is also one of the app's CLSIDs or harvested
//!   tokens, so every class value naming it is a hit), at least one class names it, and every class
//!   naming it is one of the app's classes offered under (a). `AppID\<exe name>`: only when its `AppID`
//!   value names such an AppID and no other installed app has a program of that name.
//! - `TypeLib\{x}\<version>`: when every `win16/win32/win64/arm64` path below it is a file of the app;
//!   `TypeLib\{x}` itself only when every version is a candidate.

use std::collections::HashMap;
use std::sync::OnceLock;

use purge_guard::deny::SharedIids;
use purge_guard::prefix;
use purge_index::refscan::RefHit;
use purge_index::sysobj::{Env, ProgramRef, resolve_file, resolve_program};
use purge_model::{
    Action, AnchorKind, AnchorRef, Blocker, Candidate, CandidateId, Category, Evidence,
    EvidenceKind, Facts, Scope, SourceTrust, Target, Tier,
};
use purge_source::types::{ExistsState, RegData, SourceError};

use crate::cls_progid::classes;
use crate::framework::{
    AppIdentityView, BASELINE_FACT, BASELINE_FACT_NONE, CLASSES_REDIRECTED, Dangling, RootSpec,
    ScanCtx, Scanner, anchor_trust, weakest,
};

/// The scanner's catalog id.
pub const ID: &str = "COM-CLASS";

/// The locations the scanner reads: `CLSID\{x}` with its server subkeys and their version subkeys,
/// `AppID` (its direct children), `TypeLib\{x}\<version>\<lcid>\<platform>`.
const ROOTS: &[RootSpec] = &[
    RootSpec::reg(r"HKCR\CLSID", Some(3)),
    RootSpec::reg(r"HKCR\AppID", Some(1)),
    RootSpec::reg(r"HKCR\TypeLib", Some(4)),
];

/// The COM-CLASS scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComClass;

impl Scanner for ComClass {
    fn reads_ref_walk(&self) -> bool {
        true
    }

    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let Some(hits) = walk_hits(ctx) else {
            ctx.ext.warn(ID, NO_WALK);
            return Vec::new();
        };
        let Some(kb) = shared_iids() else {
            ctx.ext.warn(ID, NO_KB);
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut classes = ClassCache::new(ctx, ID, hits, kb);
        // Classes, every view.
        for clsid in anchor_ids(&ctx.fp.anchors.clsids) {
            for place in places(ctx, "CLSID") {
                if let Some(candidate) = classes.get(ctx, &place, &clsid).candidate.clone() {
                    out.push(candidate);
                }
            }
        }
        // AppIDs.
        let mut offered_appids: Vec<OfferedAppId> = Vec::new();
        for appid in anchor_ids(&ctx.fp.anchors.appids) {
            for place in places(ctx, "AppID") {
                if let Some((candidate, offered)) =
                    appid_candidate(ctx, app, &mut classes, &place, &appid)
                {
                    out.push(candidate);
                    offered_appids.extend(offered);
                }
            }
        }
        out.extend(appid_exe_candidates(ctx, &offered_appids));
        // Type libraries.
        for typelib in anchor_ids(&ctx.fp.anchors.typelibs) {
            for place in places(ctx, "TypeLib") {
                let scan = scan_typelib(ctx, &place, &typelib);
                out.extend(scan.candidates);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------------------
// Shared with COM-INTERFACE
// ---------------------------------------------------------------------------------------------------------

/// The machine's Classes root.
pub(crate) const HKLM_CLASSES: &str = r"HKLM\SOFTWARE\Classes";

/// The 32-bit node.
const WOW: &str = "WOW6432Node";

/// The subkeys COM defines for a `CLSID\{x}` key. Anything else (an `Instance` list other products
/// add to, a `shellex` key) may hold what is not the app's, and the key is then not proven the app's
/// alone.
pub(crate) const STANDARD_CLASS_SUBKEYS: &[&str] = &[
    "InprocServer32",
    "LocalServer32",
    "InprocHandler32",
    "InprocServer",
    "LocalServer",
    "InprocHandler",
    "ProgID",
    "VersionIndependentProgID",
    "TypeLib",
    "Version",
    "Implemented Categories",
    "Required Categories",
    "Programmable",
    "Control",
    "Insertable",
    "MiscStatus",
    "ToolboxBitmap32",
    "DefaultIcon",
    "AuxUserType",
    "Verb",
    "DataFormats",
    "Conversion",
    "DefaultExtension",
    "Elevation",
    "TreatAs",
    "AutoTreatAs",
    "AutoConvertTo",
];

/// The values COM defines for an `AppID\{x}` key.
const STANDARD_APPID_VALUES: &[&str] = &[
    "",
    "AppID",
    "AppIDFlags",
    "AccessPermission",
    "ActivateAtStorage",
    "AuthenticationLevel",
    "DllSurrogate",
    "DllSurrogateExecutable",
    "Endpoints",
    "LaunchPermission",
    "LoadUserSettings",
    "LocalService",
    "PreferredServerBitness",
    "RemoteServerName",
    "ROTFlags",
    "RunAs",
    "ServiceParameters",
    "SRPTrustLevel",
];

/// The platform subkeys of a type library's locale key.
const TYPELIB_PLATFORMS: &[&str] = &["win16", "win32", "win64", "arm64"];

/// The scan warning when the context holds no reference walk for the app (S-COMMON).
pub(crate) const NO_WALK: &str =
    "the shared reference walk was not run for this app; no COM registration is offered";
/// The scan warning when `kb/shared-iids.json` does not load.
pub(crate) const NO_KB: &str =
    "kb/shared-iids.json could not be read; no COM registration is offered";

/// One scan warning for a key the scanner needed and could not read (S-COMMON: what it would have
/// offered from that key is left out). "Not there" is no warning.
pub(crate) fn warn_unread(ctx: &ScanCtx<'_>, scanner: &str, key: &str, error: &SourceError) {
    if !matches!(error, SourceError::NotFound) {
        ctx.ext.warn(
            scanner,
            format!("{key}: not read ({error}); nothing is offered from it"),
        );
    }
}

/// The `kb/shared-iids.json` lists, read once; `None` when they do not load (then nothing is offered).
pub(crate) fn shared_iids() -> Option<&'static SharedIids> {
    static KB: OnceLock<Option<SharedIids>> = OnceLock::new();
    KB.get_or_init(|| purge_guard::deny::shared_iids().ok())
        .as_ref()
}

/// The hits of the one reference walk for this context's app; `None` when the context holds none.
pub(crate) fn walk_hits<'a>(ctx: &ScanCtx<'a>) -> Option<&'a [RefHit]> {
    ctx.ext.ref_hits_for(&ctx.fp.app.program_id)
}

/// `{8-4-4-4-12}` hex digits.
pub(crate) fn is_braced_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The id without braces and blanks.
pub(crate) fn bare(id: &str) -> &str {
    id.trim().trim_start_matches('{').trim_end_matches('}')
}

/// Whether two GUIDs are the same id, braces and case ignored.
pub(crate) fn same_id(a: &str, b: &str) -> bool {
    let (a, b) = (bare(a), bare(b));
    !a.is_empty() && a.eq_ignore_ascii_case(b)
}

/// The well-formed ids of an anchor list, braced, each once, in the list's order.
pub(crate) fn anchor_ids(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for id in list {
        let braced = format!("{{{}}}", bare(id));
        if is_braced_guid(&braced) && !out.iter().any(|o| same_id(o, &braced)) {
            out.push(braced);
        }
    }
    out
}

/// Whether `id` is one of the app's anchor ids of `list`.
pub(crate) fn is_anchor(list: &[String], id: &str) -> bool {
    list.iter().any(|a| same_id(a, id))
}

/// Whether `kind` (`CLSID`, `Interface`, ...) exists once per registry view.
pub(crate) fn redirected(kind: &str) -> bool {
    CLASSES_REDIRECTED.iter().any(|r| prefix::eq_ci(r, kind))
}

/// One registry view of one Classes root: the machine's or a user's, 64-bit or 32-bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Place {
    /// `HKLM\SOFTWARE\Classes` or `HKU\<SID>_Classes`.
    pub(crate) root: String,
    /// The 32-bit view (`...\WOW6432Node`).
    pub(crate) wow: bool,
}

impl Place {
    /// The key `kind\id` of this view, spelled through the physical key.
    pub(crate) fn key(&self, kind: &str, id: &str) -> String {
        if self.wow && redirected(kind) {
            format!(r"{}\{WOW}\{kind}\{id}", self.root)
        } else {
            format!(r"{}\{kind}\{id}", self.root)
        }
    }

    /// The other view of the same root.
    pub(crate) fn twin(&self) -> Place {
        Place {
            root: self.root.clone(),
            wow: !self.wow,
        }
    }

    /// The machine's view of the same bitness.
    pub(crate) fn machine(&self) -> Place {
        Place {
            root: HKLM_CLASSES.to_owned(),
            wow: self.wow,
        }
    }

    /// Whether this is the machine's Classes.
    pub(crate) fn is_machine(&self) -> bool {
        prefix::eq_ci(&self.root, HKLM_CLASSES)
    }

    /// Whether two places are one view of one root.
    pub(crate) fn same(&self, other: &Place) -> bool {
        self.wow == other.wow && prefix::eq_ci(&self.root, &other.root)
    }

    /// A folded key for maps.
    fn fold_key(&self, id: &str) -> String {
        format!(
            "{}|{}|{}",
            prefix::fold(&self.root),
            self.wow,
            bare(id).to_ascii_lowercase()
        )
    }
}

/// The user SIDs whose Classes are looked at: the users of [`classes::user_sids`] whose hives the shared
/// reference walk covered (the fingerprint's user and the hive of a per-user registration). In any other
/// hive no referrer of a class would be known, and an unknown referrer never makes a candidate.
pub(crate) fn walked_user_sids(ctx: &ScanCtx<'_>) -> Vec<String> {
    let walked: Vec<&str> = [
        Some(ctx.fp.user_sid.as_str()),
        ctx.fp.app.program_id.hive_sid(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .collect();
    classes::user_sids(ctx)
        .into_iter()
        .filter(|sid| walked.iter().any(|w| prefix::eq_ci(w, sid)))
        .collect()
}

/// The Classes roots: the machine's, then each walked user's.
pub(crate) fn classes_roots(ctx: &ScanCtx<'_>) -> Vec<String> {
    std::iter::once(HKLM_CLASSES.to_owned())
        .chain(
            walked_user_sids(ctx)
                .into_iter()
                .map(|sid| format!(r"HKU\{sid}_Classes")),
        )
        .collect()
}

/// Every view `kind` exists in: both views of each root for a redirected kind, one otherwise.
pub(crate) fn places(ctx: &ScanCtx<'_>, kind: &str) -> Vec<Place> {
    let views: &[bool] = if redirected(kind) {
        &[false, true]
    } else {
        &[false]
    };
    classes_roots(ctx)
        .into_iter()
        .flat_map(|root| {
            views.iter().map(move |&wow| Place {
                root: root.clone(),
                wow,
            })
        })
        .collect()
}

/// A key below a Classes root, split into its view and the segments below the root.
pub(crate) struct ClassesKey<'k> {
    /// The view; `wow` is set for a 32-bit spelling, whether or not the kind is redirected.
    pub(crate) place: Place,
    /// The segments below the root (and below `WOW6432Node`).
    pub(crate) rest: Vec<&'k str>,
}

/// Splits a key below the machine's Classes (`HKLM\SOFTWARE\Classes[\WOW6432Node]`, or the link
/// spelling `HKLM\SOFTWARE\WOW6432Node\Classes`) or a user's (`HKU\<SID>_Classes[\WOW6432Node]`,
/// `HKU\<SID>\Software\Classes[\WOW6432Node]`). `None` for any other key.
pub(crate) fn split_classes(key: &str) -> Option<ClassesKey<'_>> {
    let segs: Vec<&str> = prefix::segments(key).collect();
    let is = |i: usize, want: &str| segs.get(i).is_some_and(|s| prefix::eq_ci(s, want));
    let mut wow = false;
    let (root, mut i) = if is(0, "HKLM") && is(1, "SOFTWARE") {
        if is(2, "Classes") {
            (HKLM_CLASSES.to_owned(), 3)
        } else if is(2, WOW) && is(3, "Classes") {
            wow = true;
            (HKLM_CLASSES.to_owned(), 4)
        } else {
            return None;
        }
    } else if is(0, "HKU") {
        let sid = *segs.get(1)?;
        let lower = sid.to_ascii_lowercase();
        if let Some(stem) = lower.strip_suffix("_classes") {
            (format!(r"HKU\{}_Classes", &sid[..stem.len()]), 2)
        } else if is(2, "Software") && is(3, "Classes") {
            (format!(r"HKU\{sid}_Classes"), 4)
        } else {
            return None;
        }
    } else {
        return None;
    };
    if is(i, WOW) {
        wow = true;
        i += 1;
    }
    Some(ClassesKey {
        place: Place { root, wow },
        rest: segs.get(i..)?.to_vec(),
    })
}

/// Whether the walk reports every value that names `id`: the app's reference matcher finds the id as
/// one of its CLSID or token anchors. The walk looks for nothing else.
pub(crate) fn walk_sees(app: &AppIdentityView, id: &str) -> bool {
    let braced = format!("{{{}}}", bare(id));
    app.refs.find_all(&braced).iter().any(|m| {
        matches!(m.anchor.kind, AnchorKind::Clsid | AnchorKind::Token)
            && same_id(&m.anchor.text, id)
    })
}

/// Whether a hit is a reference to `id`.
pub(crate) fn hit_names(hit: &RefHit, id: &str) -> bool {
    matches!(hit.anchor.kind, AnchorKind::Clsid | AnchorKind::Token)
        && same_id(&hit.anchor.text, id)
}

/// The machine environment as the resolvers want it; empty for a key in another user's hive, whose
/// `%NAME%` references are not this user's.
pub(crate) fn env_for(ctx: &ScanCtx<'_>, key: &str) -> Env {
    if classes::env_applies(ctx, key) {
        Env::new(ctx.env.iter())
    } else {
        Env::default()
    }
}

/// Whether the matching baseline of this Windows shows `key` is not Windows' own: it is loaded, it
/// captures the key's place, and it does not have the key.
pub(crate) fn proven_not_windows(ctx: &ScanCtx<'_>, key: &str) -> bool {
    classes::proven_not_windows(ctx, key)
}

/// What a server or type-library path is, as far as the app is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FileStand {
    /// A file of the app: inside an InstallRoot or one of its exe or outside-root files.
    Own {
        /// Canonical path.
        path: String,
        /// The trust of the root (or record) it belongs to.
        trust: SourceTrust,
        /// Whether it is there now.
        exists: ExistsState,
    },
    /// An existing file that is not the app's.
    ForeignPresent(String),
    /// A file that is not the app's and is missing, or whose state cannot be read.
    ForeignOther,
    /// No one file can be told (a host program, a relative name, an unknown reference...).
    Unresolved,
    /// Nothing is named.
    Nothing,
}

/// Classifies a resolved program.
pub(crate) fn stand_of(ctx: &ScanCtx<'_>, program: &ProgramRef) -> FileStand {
    match program {
        ProgramRef::None => FileStand::Nothing,
        ProgramRef::Unresolved { .. } => FileStand::Unresolved,
        ProgramRef::File(path) => {
            let exists = ctx.fs.exists(path);
            if ctx.object_owner(program).is_some() {
                let trust = match ctx.inside_install_root(path) {
                    Some(root) => root.trust,
                    None => anchor_trust(
                        ctx.fp,
                        &AnchorRef {
                            kind: AnchorKind::Exe,
                            text: path.clone(),
                        },
                    ),
                };
                FileStand::Own {
                    path: path.clone(),
                    trust,
                    exists,
                }
            } else if exists == ExistsState::Present {
                FileStand::ForeignPresent(path.clone())
            } else {
                FileStand::ForeignOther
            }
        }
    }
}

/// The name a blocker gives for an existing file that is not the app's: the other app it belongs to,
/// when one is known, else the file.
pub(crate) fn foreign_file_owner(ctx: &ScanCtx<'_>, path: &str) -> String {
    ctx.other_apps
        .path_blockers(path)
        .into_iter()
        .find_map(|b| match b {
            Blocker::InsideOtherApp { app } | Blocker::ReferencedByOtherApp { app } => Some(app),
            _ => None,
        })
        .unwrap_or_else(|| format!("the program {path}"))
}

/// The name a blocker gives for a COM class that is not the app's.
pub(crate) fn foreign_class_owner(ctx: &ScanCtx<'_>, clsid: &str) -> String {
    ctx.other_apps
        .claimant(AnchorKind::Clsid, clsid)
        .map_or_else(|| format!("COM class {clsid}"), |app| app.name.clone())
}

/// `ComKeyOwnership` on `key` with `trust`: Tier A only when the key is proven not Windows' own and
/// `standard` (every subkey is one COM defines); Tier B with the reason otherwise.
pub(crate) fn com_key_ownership(
    ctx: &ScanCtx<'_>,
    key: &str,
    trust: SourceTrust,
    standard: Result<(), String>,
    detail: Facts,
) -> Option<Evidence> {
    let mut evidence = Evidence::new(
        EvidenceKind::ComKeyOwnership,
        Scope::Key,
        trust,
        format!("com:{key}"),
    )?;
    let mut detail = detail;
    if !proven_not_windows(ctx, key) {
        evidence.tier = evidence.tier.at_most(Tier::B);
        detail = detail.with(BASELINE_FACT, BASELINE_FACT_NONE);
    }
    if let Err(why) = standard {
        evidence.tier = evidence.tier.at_most(Tier::B);
        detail = detail.with("unproven", why);
    }
    Some(evidence.with_detail(detail))
}

/// `DanglingRef` about the server (or type-library path) value of a COM key: the file it names is one
/// of the app's and the full dangling rule holds for it. Value scope: it is a fact about the value the
/// key holds, and adds to the key's score without standing for the key.
pub(crate) fn dangling_server(dangling: &Dangling<'_>, value_key: &str) -> Option<Evidence> {
    let evidence = Evidence::new(
        EvidenceKind::DanglingRef,
        Scope::Value,
        dangling.root().trust,
        format!("dangling:{}", dangling.path()),
    )?;
    Some(
        evidence.with_detail(
            Facts::new()
                .with("root", dangling.root().path.clone())
                .with("path", dangling.path())
                .with("value", format!(r"{value_key}|")),
        ),
    )
}

/// Whether the candidate, with the MSI blockers the sealing will add, carries a hard blocker.
pub(crate) fn hard_blocked(ctx: &ScanCtx<'_>, candidate: &Candidate) -> bool {
    candidate.has_hard_blocker()
        || ctx
            .msi_blockers(&candidate.target)
            .iter()
            .any(Blocker::is_hard)
}

// ---------------------------------------------------------------------------------------------------------
// Classes
// ---------------------------------------------------------------------------------------------------------

/// What one view of one class is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClassState {
    /// The key does not exist.
    Absent,
    /// The key, or a value needed, could not be read.
    Unreadable,
    /// Windows has the key.
    Baseline,
    /// No candidate: no server, a server that is not one file, a missing server outside the app, a
    /// .NET class without `CodeBase`.
    NotOffered(&'static str),
    /// (c) A server is an existing file outside the app.
    Foreign(String),
    /// (a)/(b) Every server is a file of the app.
    Own(Vec<OwnServer>),
}

/// A server of the app's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnServer {
    /// The server subkey (`...\InprocServer32`).
    pub(crate) value_key: String,
    /// The file.
    pub(crate) path: String,
    /// The trust of its root.
    pub(crate) trust: SourceTrust,
    /// Whether it is there.
    pub(crate) exists: ExistsState,
}

/// How a class is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Offer {
    /// (a): every server missing.
    Dangling,
    /// (b): a server present (or its state unknown).
    Present,
}

/// One view of one class, judged.
#[derive(Debug, Clone)]
pub(crate) struct ClassView {
    /// The key.
    pub(crate) key: String,
    /// What it is.
    pub(crate) state: ClassState,
    /// The candidate, when one is listed (offered or protected).
    pub(crate) candidate: Option<Candidate>,
    /// How it is offered: `Some` only for an (a)/(b) candidate without a hard blocker.
    pub(crate) offer: Option<Offer>,
    /// The `DanglingRef` evidence of an (a) candidate whose every server passed the full rule.
    pub(crate) dangling: Vec<Evidence>,
    /// The trust of its `ComKeyOwnership`.
    pub(crate) trust: SourceTrust,
    /// Why the candidate was capped at Tier B because "no other referrer" could not be concluded from
    /// the walk (R3a S3); `dangling` is empty then, so nothing built on the class is Safe either.
    pub(crate) capped: Option<&'static str>,
}

/// Why no other referrer can be concluded from the walk (R3a S3): it did not read every key of its scope.
pub(crate) const WALK_INCOMPLETE: &str =
    "the reference walk did not read every key; another referrer may have been missed";
/// Why no other referrer of a machine registration can be concluded (R3a S3): a loaded user hive the
/// walk did not cover may hold a class that names it.
pub(crate) const UNWALKED_HIVES: &str =
    "a loaded user hive was not walked; a class there may name this machine registration";
/// The scan warning when the walk is incomplete (R3a S3).
pub(crate) const WARN_WALK_INCOMPLETE: &str = "the shared reference walk did not read every key \
     (budget or unreadable keys): no COM registration is Safe on the walk's word that nothing else \
     refers to it";

/// Whether a loaded user hive was not covered by the reference walk (the walk covers the fingerprint's
/// user and the hive of a per-user registration), or the loaded hives cannot be listed.
fn unwalked_user_hives(ctx: &ScanCtx<'_>) -> bool {
    let walked: Vec<&str> = [
        Some(ctx.fp.user_sid.as_str()),
        ctx.fp.app.program_id.hive_sid(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .collect();
    let is_user = |sid: &str| {
        let sid = sid.trim().to_ascii_uppercase();
        (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
            && !sid.ends_with("_CLASSES")
            && !sid.contains(prefix::SEP)
    };
    let Ok(loaded) = ctx.reg.loaded_user_sids() else {
        return true;
    };
    loaded
        .iter()
        .chain(ctx.guard.loaded_sids.iter())
        .filter(|sid| is_user(sid))
        .any(|sid| !walked.iter().any(|w| prefix::eq_ci(w, sid.trim())))
}

/// The class views judged so far, so that COM-INTERFACE and the AppIDs read each class once.
pub(crate) struct ClassCache<'h> {
    hits: &'h [RefHit],
    kb: &'static SharedIids,
    views: HashMap<String, ClassView>,
    /// Why no other referrer of a registration in a user's Classes can be concluded (R3a S3).
    user_unknown: Option<&'static str>,
    /// The same for the machine's Classes.
    machine_unknown: Option<&'static str>,
}

impl<'h> ClassCache<'h> {
    /// An empty cache over the walk's hits. Says once (as `scanner`'s warning) when the walk is
    /// incomplete.
    pub(crate) fn new(
        ctx: &ScanCtx<'_>,
        scanner: &str,
        hits: &'h [RefHit],
        kb: &'static SharedIids,
    ) -> Self {
        let user_unknown = (!ctx.ext.ref_walk_complete()).then_some(WALK_INCOMPLETE);
        if user_unknown.is_some() {
            ctx.ext.warn(scanner, WARN_WALK_INCOMPLETE);
        }
        let machine_unknown =
            user_unknown.or_else(|| unwalked_user_hives(ctx).then_some(UNWALKED_HIVES));
        Self {
            hits,
            kb,
            views: HashMap::new(),
            user_unknown,
            machine_unknown,
        }
    }

    /// Why "no other referrer" cannot be concluded from the walk's hits for a registration at `place`
    /// (R3a S3); `None` when it can. A candidate that rests on it is capped at Tier B with this reason.
    pub(crate) fn referrers_unknown(&self, place: &Place) -> Option<&'static str> {
        if place.is_machine() {
            self.machine_unknown
        } else {
            self.user_unknown
        }
    }

    /// The view `place` of class `clsid`, read and judged on first use.
    pub(crate) fn get(&mut self, ctx: &ScanCtx<'_>, place: &Place, clsid: &str) -> &ClassView {
        let map_key = place.fold_key(clsid);
        if !self.views.contains_key(&map_key) {
            let unknown = self.referrers_unknown(place);
            let view = judge_class(ctx, self.hits, self.kb, place, clsid, unknown);
            self.views.insert(map_key.clone(), view);
        }
        &self.views[&map_key]
    }

    /// The view of `clsid` COM uses for something registered at `place`: the class in the same root
    /// and view when it exists there, else (for a user's registration) the machine's of the same view.
    pub(crate) fn resolve(&mut self, ctx: &ScanCtx<'_>, place: &Place, clsid: &str) -> &ClassView {
        let own_root = self.get(ctx, place, clsid).state != ClassState::Absent;
        if own_root || place.is_machine() {
            self.get(ctx, place, clsid)
        } else {
            self.get(ctx, &place.machine(), clsid)
        }
    }
}

/// Reads and judges one view of one class. An app's class only: `clsid` is one of its anchors.
fn judge_class(
    ctx: &ScanCtx<'_>,
    hits: &[RefHit],
    kb: &SharedIids,
    place: &Place,
    clsid: &str,
    referrers_unknown: Option<&'static str>,
) -> ClassView {
    let key = place.key("CLSID", clsid);
    let mut view = ClassView {
        key: key.clone(),
        state: ClassState::Absent,
        candidate: None,
        offer: None,
        dangling: Vec::new(),
        trust: SourceTrust::AdminOnly,
        capped: None,
    };
    // A shared proxy/stub class is never a candidate, and nothing is read of it.
    if kb.is_shared_proxy_clsid(clsid) || !is_anchor(&ctx.fp.anchors.clsids, clsid) {
        view.state = ClassState::NotOffered("not one of the app's classes");
        return view;
    }
    let (state, subkeys) = read_class(ctx, &key);
    view.state = state;
    let servers = match &view.state {
        ClassState::Own(servers) => servers.clone(),
        ClassState::Foreign(file) => {
            let mut b = ctx.candidate(
                ID,
                Target::RegKey { path: key.clone() },
                Action::DeleteKey,
                Category::ShellCom,
            );
            b.blocker(Blocker::ReferencedByOtherApp {
                app: foreign_file_owner(ctx, file),
            });
            b.common_blockers();
            view.candidate = Some(b.build());
            return view;
        }
        _ => return view,
    };
    let standard = match subkeys
        .iter()
        .find(|s| !STANDARD_CLASS_SUBKEYS.iter().any(|w| prefix::eq_ci(w, s)))
    {
        Some(other) => Err(format!(
            "the key has the subkey {other}, which is not a class's"
        )),
        None => Ok(()),
    };
    let trust = servers
        .iter()
        .fold(SourceTrust::AdminOnly, |t, s| weakest(t, s.trust));
    view.trust = trust;
    let all_missing = servers.iter().all(|s| s.exists == ExistsState::Absent);
    let detail = servers.iter().enumerate().fold(Facts::new(), |f, (i, s)| {
        f.with(format!("server{i}"), s.path.clone())
    });
    let mut b = ctx.candidate(
        ID,
        Target::RegKey { path: key.clone() },
        Action::DeleteKey,
        Category::ShellCom,
    );
    b.evidence_also(com_key_ownership(ctx, &key, trust, standard, detail));
    if all_missing {
        let dangling: Vec<Evidence> = servers
            .iter()
            .map_while(|s| {
                ctx.dangling(&s.path)
                    .and_then(|d| dangling_server(&d, &s.value_key))
            })
            .collect();
        if dangling.len() == servers.len() {
            b.evidence_also(dangling.iter().cloned());
            view.dangling = dangling;
        }
    }
    for blocker in class_referrer_blockers(ctx, hits, kb, clsid) {
        b.blocker(blocker);
    }
    // R3a S3: no `TreatAs` or shared-IID referrer seen is "none" only when the walk saw everything.
    if let Some(why) = referrers_unknown {
        b.cap_at_tier_b(why);
        view.dangling.clear();
        view.capped = Some(why);
    }
    if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::Clsid, clsid) {
        b.blocker(blocker);
    }
    if ctx.predates_install(&key) {
        b.blocker(Blocker::ExistedBeforeInstall);
    }
    b.common_blockers();
    let candidate = b.build();
    if !hard_blocked(ctx, &candidate) {
        view.offer = Some(if all_missing {
            Offer::Dangling
        } else {
            Offer::Present
        });
    }
    view.candidate = Some(candidate);
    view
}

/// The blockers other registrations give a class (from the walk's hits): another class that names it in
/// `TreatAs` or `AutoTreatAs`, and an interface listed in `kb/shared-iids.json` that names it as its
/// proxy. Every view of the class is protected: COM resolves an emulation or a proxy in whichever view
/// the client runs in.
pub(crate) fn class_referrer_blockers(
    ctx: &ScanCtx<'_>,
    hits: &[RefHit],
    kb: &SharedIids,
    clsid: &str,
) -> Vec<Blocker> {
    let mut out: Vec<Blocker> = Vec::new();
    for hit in hits.iter().filter(|h| hit_names(h, clsid)) {
        let Some(at) = split_classes(&hit.key) else {
            continue;
        };
        let rest = &at.rest;
        let leaf_is =
            |want: &[&str]| rest.len() == 3 && want.iter().any(|w| prefix::eq_ci(w, rest[2]));
        let blocker = if prefix::eq_ci(rest.first().copied().unwrap_or(""), "CLSID")
            && leaf_is(&["TreatAs", "AutoTreatAs"])
            && !is_anchor(&ctx.fp.anchors.clsids, rest[1])
        {
            Some(Blocker::ReferencedByOtherApp {
                app: foreign_class_owner(ctx, rest[1]),
            })
        } else if prefix::eq_ci(rest.first().copied().unwrap_or(""), "Interface")
            && leaf_is(&["ProxyStubClsid32", "ProxyStubClsid"])
            && kb.is_shared_iid(rest[1])
        {
            Some(Blocker::SharedIid)
        } else {
            None
        };
        if let Some(blocker) = blocker
            && !out.contains(&blocker)
        {
            out.push(blocker);
        }
    }
    out
}

/// Reads a class key and its servers; also gives the key's subkey names.
fn read_class(ctx: &ScanCtx<'_>, key: &str) -> (ClassState, Vec<String>) {
    let names = match ctx.reg.subkeys(key) {
        Ok(names) => names,
        Err(SourceError::NotFound) => return (ClassState::Absent, Vec::new()),
        Err(e) => {
            warn_unread(ctx, ID, key, &e);
            return (ClassState::Unreadable, Vec::new());
        }
    };
    if ctx.in_baseline(&Target::RegKey {
        path: key.to_owned(),
    }) {
        return (ClassState::Baseline, names);
    }
    let state = class_state(ctx, key, &names);
    (state, names)
}

/// What the servers named below `key` (whose subkeys are `names`) make of the class.
fn class_state(ctx: &ScanCtx<'_>, key: &str, names: &[String]) -> ClassState {
    let env = env_for(ctx, key);
    let find = |want: &str| names.iter().find(|n| prefix::eq_ci(n, want));
    let mut stands: Vec<(String, FileStand)> = Vec::new();
    if let Some(name) = find("InprocServer32") {
        let value_key = format!(r"{key}\{name}");
        match inproc_servers(ctx, &value_key, &env) {
            Ok(found) => stands.extend(found.into_iter().map(|s| (value_key.clone(), s))),
            Err(state) => return state,
        }
    }
    if let Some(name) = find("LocalServer32") {
        let value_key = format!(r"{key}\{name}");
        match default_string(ctx, &value_key) {
            Ok(Some(raw)) => stands.push((value_key, stand_of(ctx, &resolve_program(&raw, &env)))),
            Ok(None) => {}
            Err(()) => return ClassState::Unreadable,
        }
    }
    if stands.is_empty()
        && let Some(name) = find("InprocHandler32")
    {
        let value_key = format!(r"{key}\{name}");
        match default_string(ctx, &value_key) {
            Ok(Some(raw)) => stands.push((value_key, stand_of(ctx, &resolve_file(&raw, &env)))),
            Ok(None) => {}
            Err(()) => return ClassState::Unreadable,
        }
    }
    let mut own: Vec<OwnServer> = Vec::new();
    let mut unresolved = false;
    for (value_key, stand) in stands {
        match stand {
            FileStand::ForeignPresent(file) => return ClassState::Foreign(file),
            FileStand::Own {
                path,
                trust,
                exists,
            } => own.push(OwnServer {
                value_key,
                path,
                trust,
                exists,
            }),
            FileStand::ForeignOther | FileStand::Unresolved => unresolved = true,
            FileStand::Nothing => {}
        }
    }
    if unresolved {
        ClassState::NotOffered("a server that is not one file of the app")
    } else if own.is_empty() {
        ClassState::NotOffered("no server")
    } else {
        ClassState::Own(own)
    }
}

/// The default string of `key`: `Ok(None)` when there is none (or it is empty), `Err` when it cannot
/// be read.
fn default_string(ctx: &ScanCtx<'_>, key: &str) -> Result<Option<String>, ()> {
    match ctx.reg.value(key, "") {
        Ok(data) => Ok(string_of(&data)),
        Err(SourceError::NotFound) => Ok(None),
        Err(e) => {
            warn_unread(ctx, ID, key, &e);
            Err(())
        }
    }
}

/// The trimmed string of `data`, `None` when it is no complete string or is empty.
fn string_of(data: &RegData) -> Option<String> {
    if !data.is_complete() {
        return None;
    }
    data.string()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The servers of an `InprocServer32` key: its default path, or for `mscoree.dll` the `CodeBase`
/// files (of the key, else of its version subkeys).
fn inproc_servers(ctx: &ScanCtx<'_>, key: &str, env: &Env) -> Result<Vec<FileStand>, ClassState> {
    let values = match ctx.reg.values(key) {
        Ok(values) => values,
        Err(SourceError::NotFound) => return Ok(Vec::new()),
        Err(e) => {
            warn_unread(ctx, ID, key, &e);
            return Err(ClassState::Unreadable);
        }
    };
    let get = |values: &[purge_source::types::RegValue], name: &str| {
        values
            .iter()
            .find(|v| prefix::eq_ci(&v.name, name))
            .and_then(|v| string_of(&v.data))
    };
    let Some(default) = get(&values, "") else {
        return Ok(Vec::new());
    };
    if !is_mscoree(&default) {
        return Ok(vec![stand_of(ctx, &resolve_file(&default, env))]);
    }
    // A .NET class: the assembly's CodeBase, in the key or in its version subkeys.
    let mut code_bases: Vec<String> = get(&values, "CodeBase").into_iter().collect();
    if code_bases.is_empty() {
        let versions = match ctx.reg.subkeys(key) {
            Ok(v) => v,
            Err(SourceError::NotFound) => Vec::new(),
            Err(e) => {
                warn_unread(ctx, ID, key, &e);
                return Err(ClassState::Unreadable);
            }
        };
        for version in versions.iter().take(MAX_CLR_VERSIONS) {
            let version_key = format!(r"{key}\{version}");
            match ctx.reg.values(&version_key) {
                Ok(values) => code_bases.extend(get(&values, "CodeBase")),
                Err(e) => {
                    warn_unread(ctx, ID, &version_key, &e);
                    return Err(ClassState::Unreadable);
                }
            }
        }
        if versions.len() > MAX_CLR_VERSIONS {
            return Err(ClassState::NotOffered("too many runtime versions to read"));
        }
    }
    if code_bases.is_empty() {
        return Err(ClassState::NotOffered(
            "a .NET class without CodeBase (in the global assembly cache)",
        ));
    }
    Ok(code_bases
        .iter()
        .map(|uri| match code_base_path(uri) {
            Some(path) => stand_of(ctx, &resolve_file(&path, env)),
            None => FileStand::Unresolved,
        })
        .collect())
}

/// The most version subkeys of a .NET class's `InprocServer32` read for a `CodeBase`.
const MAX_CLR_VERSIONS: usize = 4;

/// Whether an `InprocServer32` default names the .NET runtime shim.
fn is_mscoree(default: &str) -> bool {
    let path = default.trim().trim_matches('"');
    let leaf = path.rsplit(['\\', '/']).next().unwrap_or(path);
    leaf.eq_ignore_ascii_case("mscoree.dll") || leaf.eq_ignore_ascii_case("mscoree")
}

/// The drive path a `CodeBase` names: `file:///C:/dir/x.dll` (percent escapes decoded), or a plain
/// drive path. `None` for anything else (a UNC host, another scheme, a bad escape).
pub(crate) fn code_base_path(uri: &str) -> Option<String> {
    let text = uri.trim();
    let rest = match text.get(..8) {
        Some(head) if head.eq_ignore_ascii_case("file:///") => &text[8..],
        _ => text,
    };
    let bytes = rest.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = rest.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let path = String::from_utf8(out).ok()?.replace('/', "\\");
    let b = path.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\').then_some(path)
}

// ---------------------------------------------------------------------------------------------------------
// AppIDs
// ---------------------------------------------------------------------------------------------------------

/// An AppID offered in one Classes root, for its `AppID\<exe>` keys.
#[derive(Debug, Clone)]
struct OfferedAppId {
    root: String,
    appid: String,
    key: String,
    tier: Tier,
}

/// The `AppID\{x}` candidate of `place`, with what it offers for the `AppID\<exe>` keys.
fn appid_candidate(
    ctx: &ScanCtx<'_>,
    app: &AppIdentityView,
    classes: &mut ClassCache<'_>,
    place: &Place,
    appid: &str,
) -> Option<(Candidate, Option<OfferedAppId>)> {
    // Without the walk seeing the id, a class of another product naming it would not be known.
    if !walk_sees(app, appid) {
        return None;
    }
    let key = place.key("AppID", appid);
    let values = ctx
        .reg
        .values(&key)
        .map_err(|e| warn_unread(ctx, ID, &key, &e))
        .ok()?;
    if ctx.in_baseline(&Target::RegKey { path: key.clone() }) {
        return None;
    }
    let subkeys = ctx
        .reg
        .subkeys(&key)
        .map_err(|e| warn_unread(ctx, ID, &key, &e))
        .ok()?;
    // Every class that names it: one of the app's, offered under (a).
    let hits = classes.hits;
    let referrers: Vec<(Place, String)> = hits
        .iter()
        .filter(|h| h.value_name.eq_ignore_ascii_case("AppID") && hit_names(h, appid))
        .filter_map(|h| {
            let at = split_classes(&h.key)?;
            (at.rest.len() == 2 && prefix::eq_ci(at.rest[0], "CLSID"))
                .then(|| (at.place.clone(), at.rest[1].to_owned()))
        })
        .collect();
    // Hits on value `AppID` anywhere else (not a class key) are somebody's reference too.
    let stray = hits.iter().any(|h| {
        h.value_name.eq_ignore_ascii_case("AppID")
            && hit_names(h, appid)
            && !split_classes(&h.key).is_some_and(|at| {
                (at.rest.len() == 2 && prefix::eq_ci(at.rest[0], "CLSID"))
                    || (at.rest.len() == 2 && prefix::eq_ci(at.rest[0], "AppID"))
            })
    });
    if referrers.is_empty() || stray {
        return None;
    }
    let mut trust = SourceTrust::AdminOnly;
    let mut chain: Option<String> = None;
    // R3a S3: "every class naming it is the app's" holds only when the walk saw every class that could.
    let mut unknown = classes.referrers_unknown(place);
    for (at, clsid) in &referrers {
        if !is_anchor(&ctx.fp.anchors.clsids, clsid) {
            return None;
        }
        let view = classes.get(ctx, at, clsid);
        if view.offer != Some(Offer::Dangling) {
            return None;
        }
        unknown = unknown.or(view.capped);
        trust = weakest(trust, view.trust);
        chain.get_or_insert_with(|| view.key.clone());
    }
    // A surrogate that is not Windows' default must be the app's.
    if let Some(surrogate) = values
        .iter()
        .find(|v| prefix::eq_ci(&v.name, "DllSurrogate"))
        .and_then(|v| string_of(&v.data))
    {
        let env = env_for(ctx, &key);
        if !matches!(
            stand_of(ctx, &resolve_file(&surrogate, &env)),
            FileStand::Own { .. }
        ) {
            return None;
        }
    }
    let standard = match (
        values.iter().find(|v| {
            !STANDARD_APPID_VALUES
                .iter()
                .any(|w| prefix::eq_ci(w, &v.name))
        }),
        subkeys.first(),
    ) {
        (Some(v), _) => Err(format!(
            "the key has the value {}, which is not an AppID's",
            v.name
        )),
        (None, Some(s)) => Err(format!(
            "the key has the subkey {s}, which is not an AppID's"
        )),
        (None, None) => Ok(()),
    };
    let mut b = ctx.candidate(
        ID,
        Target::RegKey { path: key.clone() },
        Action::DeleteKey,
        Category::ShellCom,
    );
    let ownership = com_key_ownership(
        ctx,
        &key,
        trust,
        standard,
        Facts::new().with("named_by", referrers.len().to_string()),
    );
    let mut tier = ownership.as_ref().map_or(Tier::B, |e| e.tier);
    b.evidence_also(ownership);
    if let Some(class_key) = &chain {
        b.chained_ref(tier, class_key);
    }
    if let Some(why) = unknown {
        b.cap_at_tier_b(why);
        tier = Tier::B;
    }
    if ctx.predates_install(&key) {
        b.blocker(Blocker::ExistedBeforeInstall);
    }
    b.common_blockers();
    let candidate = b.build();
    let offered = (!hard_blocked(ctx, &candidate)).then(|| OfferedAppId {
        root: place.root.clone(),
        appid: appid.to_owned(),
        key: key.clone(),
        tier,
    });
    Some((candidate, offered))
}

/// The `AppID\<exe name>` keys whose `AppID` value names an offered AppID of the same root, for the
/// file names of the app's programs. One listing of each root's `AppID` key.
fn appid_exe_candidates(ctx: &ScanCtx<'_>, offered: &[OfferedAppId]) -> Vec<Candidate> {
    let fp = ctx.fp;
    let exe_names: Vec<&str> = fp
        .exes
        .iter()
        .map(|e| e.path.as_str())
        .chain(fp.outside_root_files.iter().map(|f| f.path.as_str()))
        .filter_map(prefix::leaf)
        .collect();
    let mut roots: Vec<&str> = Vec::new();
    for o in offered {
        if !roots.iter().any(|r| prefix::eq_ci(r, &o.root)) {
            roots.push(&o.root);
        }
    }
    let mut out = Vec::new();
    for root in roots {
        let parent = format!(r"{root}\AppID");
        let names = match ctx.reg.subkeys(&parent) {
            Ok(names) => names,
            Err(e) => {
                warn_unread(ctx, ID, &parent, &e);
                continue;
            }
        };
        for name in names {
            if is_braced_guid(&name) || !exe_names.iter().any(|e| prefix::eq_ci(e, &name)) {
                continue;
            }
            let key = format!(r"{parent}\{name}");
            let (values, subkeys) = match (ctx.reg.values(&key), ctx.reg.subkeys(&key)) {
                (Ok(values), Ok(subkeys)) => (values, subkeys),
                (Err(e), _) | (_, Err(e)) => {
                    warn_unread(ctx, ID, &key, &e);
                    continue;
                }
            };
            let named = values
                .iter()
                .find(|v| prefix::eq_ci(&v.name, "AppID"))
                .and_then(|v| string_of(&v.data));
            let Some(target) = named.and_then(|id| {
                offered
                    .iter()
                    .find(|o| prefix::eq_ci(&o.root, root) && same_id(&o.appid, &id))
            }) else {
                continue;
            };
            // Only the mapping: an `AppID` value (and its flags), nothing else.
            let only_mapping = subkeys.is_empty()
                && values.iter().all(|v| {
                    ["AppID", "AppIDFlags"]
                        .iter()
                        .any(|w| prefix::eq_ci(w, &v.name))
                });
            if !only_mapping || ctx.in_baseline(&Target::RegKey { path: key.clone() }) {
                continue;
            }
            let mut b = ctx.candidate(
                ID,
                Target::RegKey { path: key.clone() },
                Action::DeleteKey,
                Category::ShellCom,
            );
            b.chained_ref(target.tier, &target.key);
            // The key applies to every program of that name: another app's program of the same name
            // would lose its settings.
            if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::Exe, &name) {
                b.blocker(blocker);
            }
            b.common_blockers();
            out.push(b.build());
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// Type libraries
// ---------------------------------------------------------------------------------------------------------

/// What COM-CLASS found for one type library in one root.
pub(crate) struct TypeLibScan {
    /// The candidates: one per version that qualifies, and the whole key when all do.
    pub(crate) candidates: Vec<Candidate>,
    /// The key `TypeLib\{x}`.
    pub(crate) key: String,
    /// Whether the whole key is a candidate with no hard blocker.
    pub(crate) whole_offered: bool,
    /// What the type library is now (R3a S2).
    pub(crate) standing: TypeLibStanding,
}

/// What a type library of the app is now, as [`scan_typelib`] read it (R3a S2). The worst finding wins:
/// a foreign file over an unreadable key over a version of the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypeLibStanding {
    /// At least one version is a candidate (every platform path a file of the app).
    Own,
    /// A platform path is an existing file outside the app: another product registered the library.
    Foreign(String),
    /// The key is gone.
    Absent,
    /// A key or value could not be read.
    Unreadable,
    /// Not the app's now: not an anchor, in the baseline, no version, or files that cannot be told.
    NotOwn,
}

/// The version of a type library: its candidate and what its files are.
struct VersionScan {
    candidate: Option<Candidate>,
    trust: SourceTrust,
    dangling: Vec<Evidence>,
    all_dangling: bool,
    /// An existing file outside the app that a platform path names.
    foreign: Option<String>,
    /// A key or value of the version could not be read.
    unreadable: bool,
}

/// Reads `TypeLib\{id}` of `place` (an app's type library) and builds its candidates.
pub(crate) fn scan_typelib(ctx: &ScanCtx<'_>, place: &Place, id: &str) -> TypeLibScan {
    let key = place.key("TypeLib", id);
    let mut scan = TypeLibScan {
        candidates: Vec::new(),
        key: key.clone(),
        whole_offered: false,
        standing: TypeLibStanding::NotOwn,
    };
    if !is_anchor(&ctx.fp.anchors.typelibs, id)
        || ctx.in_baseline(&Target::RegKey { path: key.clone() })
    {
        return scan;
    }
    let versions = match ctx.reg.subkeys(&key) {
        Ok(versions) => versions,
        Err(SourceError::NotFound) => {
            scan.standing = TypeLibStanding::Absent;
            return scan;
        }
        Err(e) => {
            warn_unread(ctx, ID, &key, &e);
            scan.standing = TypeLibStanding::Unreadable;
            return scan;
        }
    };
    let mut all = !versions.is_empty();
    let mut ids: Vec<CandidateId> = Vec::new();
    let mut trust = SourceTrust::AdminOnly;
    let mut dangling: Vec<Evidence> = Vec::new();
    let mut all_dangling = true;
    let mut foreign: Option<String> = None;
    let mut unreadable = false;
    for version in &versions {
        let version_key = format!(r"{key}\{version}");
        let v = scan_version(ctx, &version_key);
        if foreign.is_none() {
            foreign = v.foreign;
        }
        unreadable |= v.unreadable;
        match v.candidate {
            Some(candidate) => {
                all &= !hard_blocked(ctx, &candidate);
                ids.push(candidate.id.clone());
                trust = weakest(trust, v.trust);
                all_dangling &= v.all_dangling;
                dangling.extend(v.dangling);
                scan.candidates.push(candidate);
            }
            None => all = false,
        }
    }
    scan.standing = if let Some(file) = foreign {
        TypeLibStanding::Foreign(file)
    } else if unreadable {
        TypeLibStanding::Unreadable
    } else if !scan.candidates.is_empty() {
        TypeLibStanding::Own
    } else {
        TypeLibStanding::NotOwn
    };
    if !all {
        return scan;
    }
    let mut b = ctx.candidate(
        ID,
        Target::RegKey { path: key.clone() },
        Action::DeleteKey,
        Category::ShellCom,
    );
    b.evidence_also(com_key_ownership(
        ctx,
        &key,
        trust,
        Ok(()),
        Facts::new().with("versions", versions.len().to_string()),
    ));
    if all_dangling {
        b.evidence_also(dangling);
    }
    for id in ids {
        b.child(id);
    }
    if ctx.predates_install(&key) {
        b.blocker(Blocker::ExistedBeforeInstall);
    }
    b.common_blockers();
    let whole = b.build();
    scan.whole_offered = !hard_blocked(ctx, &whole);
    scan.candidates.push(whole);
    scan
}

/// One `TypeLib\{x}\<version>` key: a candidate when every platform path below it is a file of the app.
fn scan_version(ctx: &ScanCtx<'_>, version_key: &str) -> VersionScan {
    let mut out = VersionScan {
        candidate: None,
        trust: SourceTrust::AdminOnly,
        dangling: Vec::new(),
        all_dangling: false,
        foreign: None,
        unreadable: false,
    };
    if ctx.in_baseline(&Target::RegKey {
        path: version_key.to_owned(),
    }) {
        return out;
    }
    let children = match ctx.reg.subkeys(version_key) {
        Ok(children) => children,
        Err(e) => {
            warn_unread(ctx, ID, version_key, &e);
            out.unreadable = !matches!(e, SourceError::NotFound);
            return out;
        }
    };
    let env = env_for(ctx, version_key);
    let mut own: Vec<(String, String, SourceTrust, ExistsState)> = Vec::new();
    let mut nonstandard: Option<String> = None;
    // A file that is not the app's: the version is not offered, but every path is still looked at, so
    // that another product's file is found wherever it is (R3a S2).
    let mut not_own = false;
    for child in &children {
        if prefix::eq_ci(child, "FLAGS") || prefix::eq_ci(child, "HELPDIR") {
            continue;
        }
        if !child.chars().all(|c| c.is_ascii_hexdigit()) {
            nonstandard.get_or_insert_with(|| child.clone());
            continue;
        }
        let lcid_key = format!(r"{version_key}\{child}");
        let platforms = match ctx.reg.subkeys(&lcid_key) {
            Ok(platforms) => platforms,
            Err(e) => {
                warn_unread(ctx, ID, &lcid_key, &e);
                out.unreadable = !matches!(e, SourceError::NotFound);
                return out;
            }
        };
        for platform in &platforms {
            let platform_key = format!(r"{lcid_key}\{platform}");
            if !TYPELIB_PLATFORMS.iter().any(|p| prefix::eq_ci(p, platform)) {
                nonstandard.get_or_insert_with(|| format!(r"{child}\{platform}"));
                continue;
            }
            let raw = match default_string(ctx, &platform_key) {
                Ok(Some(raw)) => raw,
                Ok(None) => continue,
                Err(()) => {
                    out.unreadable = true;
                    return out;
                }
            };
            match stand_of(ctx, &resolve_file(&raw, &env)) {
                FileStand::Own {
                    path,
                    trust,
                    exists,
                } => own.push((platform_key, path, trust, exists)),
                FileStand::Nothing => {}
                FileStand::ForeignPresent(file) => {
                    out.foreign.get_or_insert(file);
                    not_own = true;
                }
                // Not every file is the app's: the version is not offered.
                FileStand::ForeignOther | FileStand::Unresolved => not_own = true,
            }
        }
    }
    if own.is_empty() || not_own {
        return out;
    }
    out.trust = own
        .iter()
        .fold(SourceTrust::AdminOnly, |t, (_, _, trust, _)| {
            weakest(t, *trust)
        });
    let missing = own.iter().all(|(_, _, _, e)| *e == ExistsState::Absent);
    let dangling: Vec<Evidence> = if missing {
        own.iter()
            .map_while(|(value_key, path, _, _)| {
                ctx.dangling(path)
                    .and_then(|d| dangling_server(&d, value_key))
            })
            .collect()
    } else {
        Vec::new()
    };
    out.all_dangling = missing && dangling.len() == own.len();
    let standard = match nonstandard {
        Some(other) => Err(format!(
            "the key has the subkey {other}, which is not a type library's"
        )),
        None => Ok(()),
    };
    let mut b = ctx.candidate(
        ID,
        Target::RegKey {
            path: version_key.to_owned(),
        },
        Action::DeleteKey,
        Category::ShellCom,
    );
    let detail = own
        .iter()
        .enumerate()
        .fold(Facts::new(), |f, (i, (_, path, _, _))| {
            f.with(format!("file{i}"), path.clone())
        });
    b.evidence_also(com_key_ownership(
        ctx,
        version_key,
        out.trust,
        standard,
        detail,
    ));
    if out.all_dangling {
        b.evidence_also(dangling.iter().cloned());
        out.dangling = dangling;
    }
    if ctx.predates_install(version_key) {
        b.blocker(Blocker::ExistedBeforeInstall);
    }
    b.common_blockers();
    out.candidate = Some(b.build());
    out
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
    fn code_base_forms() {
        assert_eq!(
            code_base_path("file:///C:/Program Files/App/x.dll").as_deref(),
            Some(r"C:\Program Files\App\x.dll")
        );
        assert_eq!(
            code_base_path("FILE:///C:/Program%20Files/App/x.dll").as_deref(),
            Some(r"C:\Program Files\App\x.dll")
        );
        assert_eq!(
            code_base_path(r"C:\App\x.dll").as_deref(),
            Some(r"C:\App\x.dll")
        );
        assert_eq!(code_base_path("file://server/share/x.dll"), None);
        assert_eq!(code_base_path("file:///C:/App/%zz.dll"), None);
        assert_eq!(code_base_path("x.dll"), None);
    }

    #[test]
    fn mscoree_is_recognised() {
        assert!(is_mscoree("mscoree.dll"));
        assert!(is_mscoree(r#""C:\Windows\System32\MSCOREE.DLL""#));
        assert!(!is_mscoree(r"C:\App\mscoreex.dll"));
    }

    #[test]
    fn split_classes_spellings() {
        let sid = "S-1-5-21-1-2-3-1001";
        let cases = [
            (
                r"HKLM\SOFTWARE\Classes\CLSID\{x}",
                HKLM_CLASSES.to_owned(),
                false,
            ),
            (
                r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{x}",
                HKLM_CLASSES.to_owned(),
                true,
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{x}",
                HKLM_CLASSES.to_owned(),
                true,
            ),
        ];
        for (key, root, wow) in cases {
            let at = split_classes(key).unwrap();
            assert_eq!(at.place, Place { root, wow }, "{key}");
            assert_eq!(at.rest, vec!["CLSID", "{x}"], "{key}");
        }
        for key in [
            format!(r"HKU\{sid}_Classes\WOW6432Node\CLSID\{{x}}"),
            format!(r"HKU\{sid}\Software\Classes\WOW6432Node\CLSID\{{x}}"),
        ] {
            let at = split_classes(&key).unwrap();
            assert_eq!(
                at.place,
                Place {
                    root: format!(r"HKU\{sid}_Classes"),
                    wow: true
                }
            );
        }
        assert!(split_classes(r"HKLM\SOFTWARE\Vendor\CLSID").is_none());
        assert!(split_classes(r"HKCR\CLSID\{x}").is_none());
    }

    #[test]
    fn places_spell_the_physical_keys() {
        let machine = Place {
            root: HKLM_CLASSES.into(),
            wow: true,
        };
        assert_eq!(
            machine.key("CLSID", "{x}"),
            r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{x}"
        );
        // AppID and TypeLib are one key for both views.
        assert_eq!(
            machine.key("AppID", "{x}"),
            r"HKLM\SOFTWARE\Classes\AppID\{x}"
        );
        assert_eq!(
            machine.key("TypeLib", "{x}"),
            r"HKLM\SOFTWARE\Classes\TypeLib\{x}"
        );
        assert_eq!(
            machine.key("Interface", "{x}"),
            r"HKLM\SOFTWARE\Classes\WOW6432Node\Interface\{x}"
        );
    }

    #[test]
    fn shared_kb_loads() {
        let kb = shared_iids().expect("kb/shared-iids.json loads");
        assert!(kb.is_shared_proxy_clsid("{00020424-0000-0000-C000-000000000046}"));
    }
}
