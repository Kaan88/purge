//! CLS-PROGID (ENGINE_PLAN.md §5.6): `Classes\<ProgID>` for the ProgIDs of the app.
//!
//! # What is looked at
//!
//! Only the physical hives, `HKLM\SOFTWARE\Classes` and `HKU\<SID>_Classes`, never `HKCR`. Below each, the
//! keys named exactly as a ProgID of the fingerprint's set **P** (§5.4), and every `*_auto_file` key.
//!
//! # What is offered
//!
//! - **The key** (`DeleteKey`), only when a baseline for exactly this Windows is loaded and does not have
//!   the key, the Inno log does not say the key existed before the install, the whole subtree could be
//!   read, and no `shell\<verb>\command` in it launches something that is not the app's. The evidence is
//!   whatever holds for this exact key: an Inno key-create record, `ProvenOwnedSkeleton`, a harvested
//!   token in the key's name, and a `ChainedRef` to what the key refers to. That chain is Tier A when a
//!   verb command launches a file of the app (present or dangling) or the harvest recorded a value below
//!   the key that pointed into an InstallRoot; a ProgID that is in P on the harvest's word alone is
//!   chained at Tier B.
//! - A `*_auto_file` key that is not in P is offered only through `ProvenOwnedSkeleton` or a command that
//!   launches a file of the app.
//! - **Values only** in every other case (no matching baseline, a ProgID Windows ships and the app
//!   modified, an unreadable subtree): each value below the key whose data points into an InstallRoot or
//!   at a file of the exe set, with `InPreUninstallRefSnapshot`, `PointsIntoInstallRoot`, `DanglingRef` or
//!   an Inno value record. Restoring the previous handler of a modified ProgID is CLS-ASSOC's job.
//!
//! # Blockers
//!
//! The common ones (baseline, TrustedInstaller, registry link, existed before the install, other apps'
//! keys), and `ReferencedByOtherApp` when another app has the ProgID among its anchors or when an `.ext`
//! default or an `OpenWithProgids` value still names the ProgID and the harvest did not record that
//! reference as the app's own (extension journal, reference snapshot or Inno value record).
//!
//! # Shared helpers
//!
//! The [`classes`] module holds what the five Classes key scanners of this package share (CLS-PROGID,
//! CLS-VERBS, CLS-PROTOCOL, CLS-AUMID, CLS-REGAPPS): the hive roots, the bounded subtree read, the
//! "does this command launch the app" test and the key / value candidate builders.

use std::cell::OnceCell;

use purge_guard::prefix;
use purge_model::{AnchorKind, Blocker, Candidate, Category, EvidenceKind, Target, Tier};

use crate::framework::{AppIdentityView, RootSpec, ScanCtx, Scanner};

use self::classes::{ClassesRoot, KeyScan};

/// The scanner's catalog id.
pub const ID: &str = "CLS-PROGID";

/// The locations the scanner reads.
const ROOTS: &[RootSpec] = &[RootSpec::reg(r"*\SOFTWARE\Classes", None)];

/// The suffix of the ProgIDs Explorer creates for "Open with" choices.
const AUTO_FILE: &str = "_auto_file";

/// The CLS-PROGID scanner.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClsProgId;

impl Scanner for ClsProgId {
    fn id(&self) -> &'static str {
        ID
    }

    fn captured_roots(&self) -> &[RootSpec] {
        ROOTS
    }

    fn scan(&self, ctx: &ScanCtx<'_>, app: &AppIdentityView) -> Vec<Candidate> {
        let progids = &ctx.fp.anchors.progids;
        let roots = classes::classes_roots(ctx);
        // Read at most once, and only when a key is about to be offered.
        let ext_refs: OnceCell<Vec<ExtRef>> = OnceCell::new();
        let mut out = Vec::new();
        for root in &roots {
            for name in root.names() {
                let in_p = progids.iter().any(|p| prefix::eq_ci(p, name));
                if !(in_p || is_auto_file(name)) || classes::is_reserved(name) {
                    continue;
                }
                let key = root.key_of(name);
                let Some(scan) = KeyScan::read(ctx, app, &key) else {
                    continue;
                };
                match key_offer(ctx, &scan, name, in_p, || {
                    ext_refs.get_or_init(|| read_ext_refs(ctx, &roots))
                }) {
                    Some(candidate) => out.push(candidate),
                    None => out.extend(classes::value_candidates(
                        ctx,
                        ID,
                        &scan,
                        Category::Association,
                    )),
                }
            }
        }
        out
    }
}

fn is_auto_file(name: &str) -> bool {
    name.len() > AUTO_FILE.len()
        && name.is_char_boundary(name.len() - AUTO_FILE.len())
        && name[name.len() - AUTO_FILE.len()..].eq_ignore_ascii_case(AUTO_FILE)
}

/// The key candidate for the ProgID key `scan` was read from, when the key itself may be offered.
fn key_offer<'r>(
    ctx: &ScanCtx<'_>,
    scan: &KeyScan,
    name: &str,
    in_p: bool,
    ext_refs: impl FnOnce() -> &'r Vec<ExtRef>,
) -> Option<Candidate> {
    if scan.foreign_command() {
        return None;
    }
    let launch = scan.launch();
    let chain: Option<(Tier, &str)> = match launch {
        Some(path) => Some((Tier::A, path)),
        None if in_p && classes::snapshot_below(ctx, &scan.key) => Some((Tier::A, name)),
        None if in_p => Some((Tier::B, name)),
        None => None,
    };
    let mut builder = classes::key_candidate(ctx, ID, scan, Category::Association, chain)?;
    let proven = builder
        .evidence()
        .iter()
        .any(|e| e.kind == EvidenceKind::ProvenOwnedSkeleton);
    // A `*_auto_file` key outside P: only as a proven skeleton or through its command.
    if !(in_p || proven || launch.is_some()) {
        return None;
    }
    if let Some(blocker) = ctx.other_apps.anchor_blocker(AnchorKind::ProgId, name) {
        builder.blocker(blocker);
    }
    for reference in ext_refs()
        .iter()
        .filter(|r| prefix::eq_ci(&r.progid, name) && !recorded_as_own(ctx, r))
    {
        builder.blocker(Blocker::ReferencedByOtherApp {
            app: referrer_name(ctx, reference),
        });
    }
    Some(builder.build())
}

/// One association that names a ProgID: an `.ext` default or an `OpenWithProgids` value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExtRef {
    /// The ProgID named.
    progid: String,
    /// The `.ext` key.
    ext_key: String,
    /// The key holding the value: the `.ext` key or its `OpenWithProgids`.
    value_key: String,
    /// The value: `""` for the `.ext` default, the ProgID for an `OpenWithProgids` value.
    value_name: String,
}

/// Every `.ext` default and `OpenWithProgids` value of the Classes roots.
fn read_ext_refs(ctx: &ScanCtx<'_>, roots: &[ClassesRoot]) -> Vec<ExtRef> {
    let mut out = Vec::new();
    for root in roots {
        for ext in root.names().filter(|n| n.starts_with('.')) {
            let ext_key = root.key_of(ext);
            let default = ctx
                .reg
                .value(&ext_key, "")
                .ok()
                .and_then(|data| data.string())
                .filter(|progid| !progid.is_empty());
            if let Some(progid) = default {
                out.push(ExtRef {
                    progid,
                    ext_key: ext_key.clone(),
                    value_key: ext_key.clone(),
                    value_name: String::new(),
                });
            }
            let open_with = format!("{ext_key}\\OpenWithProgids");
            for value in ctx.reg.values(&open_with).unwrap_or_default() {
                if !value.name.is_empty() {
                    out.push(ExtRef {
                        progid: value.name.clone(),
                        ext_key: ext_key.clone(),
                        value_key: open_with.clone(),
                        value_name: value.name,
                    });
                }
            }
        }
    }
    out
}

/// Whether the harvest recorded this association as the app's own: in the extension journal, in the
/// reference snapshot or as an Inno value record. Such a value is CLS-ASSOC's to remove and does not keep
/// the ProgID alive.
fn recorded_as_own(ctx: &ScanCtx<'_>, reference: &ExtRef) -> bool {
    let fp = ctx.fp;
    let same = |a: &str, b: &str| ctx.same_key(&classes::physical(a), &classes::physical(b));
    let is_value = |target: &Target| {
        matches!(target, Target::RegValue { path, name }
            if same(path, &reference.value_key) && prefix::eq_ci(name, &reference.value_name))
    };
    fp.ext_journal.iter().any(|entry| {
        same(&entry.key, &reference.ext_key)
            && if reference.value_name.is_empty() {
                entry
                    .default
                    .as_deref()
                    .is_some_and(|d| prefix::eq_ci(d, &reference.progid))
            } else {
                entry
                    .openwith_ours
                    .iter()
                    .any(|p| prefix::eq_ci(p, &reference.progid))
            }
    }) || fp.ref_snapshot.iter().any(|entry| is_value(&entry.target))
        || fp
            .inno
            .iter()
            .any(|record| !record.existed_before && is_value(&record.target))
}

/// Who to name in the blocker: the other app whose key the association lies in, when one is known.
fn referrer_name(ctx: &ScanCtx<'_>, reference: &ExtRef) -> String {
    ctx.other_apps
        .key_blockers(&reference.ext_key)
        .into_iter()
        .find_map(|blocker| match blocker {
            Blocker::InsideOtherApp { app } => Some(app),
            _ => None,
        })
        .unwrap_or_else(|| {
            let name = if reference.value_name.is_empty() {
                "(default)"
            } else {
                &reference.value_name
            };
            format!("unrecorded association {}|{name}", reference.value_key)
        })
}

/// What the Classes key scanners share.
pub(crate) mod classes {
    use std::collections::{BTreeMap, HashMap};

    use purge_guard::prefix;
    use purge_index::baseline_view::Absence;
    use purge_model::{
        Action, AnchorKind, Candidate, Category, FileTime, Root, RootKind, Target, Tier,
    };

    use crate::framework::{AppIdentityView, CandidateBuilder, ScanCtx};

    /// The machine Classes root.
    pub(crate) const HKLM_CLASSES: &str = r"HKLM\SOFTWARE\Classes";

    /// Direct children of a Classes root that are containers of Windows, never a ProgID or a URL scheme
    /// of an app (§5.10 lists most of them as structural).
    const RESERVED: &[&str] = &[
        "*",
        "ActivatableClasses",
        "AllFilesystemObjects",
        "AppID",
        "Applications",
        "AppUserModelId",
        "CLSID",
        "Component Categories",
        "DesktopBackground",
        "Directory",
        "Drive",
        "Extensions",
        "Folder",
        "Installer",
        "Interface",
        "LibraryFolder",
        "Local Settings",
        "Media Type",
        "MIME",
        "PackagedCom",
        "Protocols",
        "Record",
        "SystemFileAssociations",
        "TypeLib",
        "WOW6432Node",
    ];

    /// Whether `name` cannot be a ProgID or scheme key: an extension, a reserved container, or not a
    /// single segment.
    pub(crate) fn is_reserved(name: &str) -> bool {
        name.is_empty()
            || name.starts_with('.')
            || name.contains(prefix::SEP)
            || RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name))
    }

    /// The user SIDs whose hives are looked at. Service accounts are left out (their hives are never an
    /// app's, and the guard denies them).
    ///
    /// - A **machine-wide** app: the fingerprint's user first, then every loaded user hive (an app
    ///   installed for all users registers per user on first run, as Firefox does).
    /// - A **per-user** app: the fingerprint's user and the user whose hive holds the registration, no
    ///   one else. Another user can have an install of their own of the same app, with the same ProgIDs,
    ///   AUMIDs and tokens; nothing in that user's hive is a leftover of this one.
    pub(crate) fn user_sids(ctx: &ScanCtx<'_>) -> Vec<String> {
        let is_user = |sid: &str| {
            let sid = sid.to_ascii_uppercase();
            (sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-"))
                && !sid.ends_with("_CLASSES")
                && !sid.contains(prefix::SEP)
        };
        let mut sids: Vec<String> = vec![ctx.fp.user_sid.trim().to_owned()];
        match ctx.fp.app.program_id.hive_sid() {
            Some(own) => sids.push(own.trim().to_owned()),
            None => {
                sids.extend(ctx.reg.loaded_user_sids().unwrap_or_default());
                sids.extend(ctx.guard.loaded_sids.iter().cloned());
            }
        }
        let mut out: Vec<String> = Vec::new();
        for sid in sids {
            if is_user(&sid) && !out.iter().any(|known| prefix::eq_ci(known, &sid)) {
                out.push(sid);
            }
        }
        out
    }

    /// Whether the environment of the scan ([`ScanCtx::env`], the interactive user's) may be applied to
    /// strings stored under `key`: not in the hive of another user, whose `%LOCALAPPDATA%` is not this
    /// one. There a `%NAME%` reference is left as written, and so resolves to nothing of the app.
    pub(crate) fn env_applies(ctx: &ScanCtx<'_>, key: &str) -> bool {
        const SUFFIX: &str = "_classes";
        let mut segs = prefix::segments(key);
        if !segs.next().is_some_and(|r| r.eq_ignore_ascii_case("HKU")) {
            return true;
        }
        let Some(sid) = segs.next() else {
            return true;
        };
        let sid = if sid.to_ascii_lowercase().ends_with(SUFFIX) {
            &sid[..sid.len() - SUFFIX.len()]
        } else {
            sid
        };
        prefix::eq_ci(sid, ctx.fp.user_sid.trim())
    }

    /// The hive roots with their `SOFTWARE` key: `("HKLM", "HKLM\SOFTWARE")` and, per user,
    /// `("HKU\<SID>", "HKU\<SID>\Software")`.
    pub(crate) fn software_roots(ctx: &ScanCtx<'_>) -> Vec<(String, String)> {
        let mut out = vec![("HKLM".to_owned(), r"HKLM\SOFTWARE".to_owned())];
        for sid in user_sids(ctx) {
            out.push((format!("HKU\\{sid}"), format!("HKU\\{sid}\\Software")));
        }
        out
    }

    /// One physical Classes root and the names of its direct subkeys, as stored.
    pub(crate) struct ClassesRoot {
        /// The root key: `HKLM\SOFTWARE\Classes` or `HKU\<SID>_Classes`.
        pub(crate) key: String,
        names: Vec<String>,
        index: HashMap<String, usize>,
    }

    impl ClassesRoot {
        /// Reads the root; `None` when it cannot be listed.
        ///
        /// The listing is not bounded by `ScanLimits::max_key_children`: a Classes root has many
        /// thousands of subkeys on every machine and only their names are read here.
        fn read(ctx: &ScanCtx<'_>, key: String) -> Option<Self> {
            let names = ctx.reg.subkeys(&key).ok()?;
            let index = names
                .iter()
                .enumerate()
                .map(|(i, name)| (prefix::fold(name), i))
                .collect();
            Some(Self { key, names, index })
        }

        /// The subkey names, in the source's order.
        pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
            self.names.iter().map(String::as_str)
        }

        /// The key of the subkey `name` (a name of [`ClassesRoot::names`]).
        pub(crate) fn key_of(&self, name: &str) -> String {
            format!("{}\\{name}", self.key)
        }

        /// The key of the subkey called `name` in any letter case, spelled as stored.
        pub(crate) fn child(&self, name: &str) -> Option<String> {
            self.index
                .get(&prefix::fold(name))
                .map(|&i| self.key_of(&self.names[i]))
        }
    }

    /// The Classes roots that exist and can be listed: the machine's, then each user's.
    pub(crate) fn classes_roots(ctx: &ScanCtx<'_>) -> Vec<ClassesRoot> {
        std::iter::once(HKLM_CLASSES.to_owned())
            .chain(
                user_sids(ctx)
                    .into_iter()
                    .map(|sid| format!("HKU\\{sid}_Classes")),
            )
            .filter_map(|key| ClassesRoot::read(ctx, key))
            .collect()
    }

    /// The subkey of `parent` called `name` in any letter case, spelled as stored.
    pub(crate) fn existing_child(ctx: &ScanCtx<'_>, parent: &str, name: &str) -> Option<String> {
        ctx.reg
            .subkeys(parent)
            .ok()?
            .into_iter()
            .find(|n| prefix::eq_ci(n, name))
            .map(|n| format!("{parent}\\{n}"))
    }

    /// [`existing_child`] along a path of names.
    pub(crate) fn existing_path(ctx: &ScanCtx<'_>, start: &str, names: &[&str]) -> Option<String> {
        names.iter().try_fold(start.to_owned(), |key, name| {
            existing_child(ctx, &key, name)
        })
    }

    /// `HKU\<SID>\Software\Classes\…` spelled as the physical `HKU\<SID>_Classes\…`; any other key
    /// unchanged. Fingerprint records may use either spelling.
    pub(crate) fn physical(key: &str) -> String {
        let segs: Vec<&str> = prefix::segments(key).collect();
        let user_classes = segs.len() >= 4
            && segs[0].eq_ignore_ascii_case("HKU")
            && segs[2].eq_ignore_ascii_case("Software")
            && segs[3].eq_ignore_ascii_case("Classes");
        if !user_classes {
            return key.to_owned();
        }
        let mut out = format!("HKU\\{}_Classes", segs[1]);
        for seg in &segs[4..] {
            out.push(prefix::SEP);
            out.push_str(seg);
        }
        out
    }

    /// **A.** Whether the scan's view is the exact baseline of this Windows (the machine as the source
    /// reports it, else as the fingerprint recorded it): the only view whose absence is proof.
    pub(crate) fn has_matching_baseline(ctx: &ScanCtx<'_>) -> bool {
        ctx.has_matching_exact_baseline()
    }

    /// **A.** Whether the matching baseline of this Windows shows `key` is not Windows' own: it is
    /// loaded, it captures the key's place, and it does not have the key. Below Exact: never.
    pub(crate) fn proven_not_windows(ctx: &ScanCtx<'_>, key: &str) -> bool {
        has_matching_baseline(ctx) && matches!(ctx.key_absence(key), Absence::Proven)
    }

    /// Whether `key` may be offered as a key at all: a matching baseline is loaded, the key is in the
    /// scope baselines capture and is not in it, and no Inno record says it existed before the install.
    /// Otherwise the scanners work values-only on it (§5.7.1 step 3, §5.4 "pre-existing ProgIDs").
    pub(crate) fn key_offerable(ctx: &ScanCtx<'_>, key: &str) -> bool {
        proven_not_windows(ctx, key)
            && !ctx.fp.inno.iter().any(|record| {
                record.existed_before
                    && matches!(&record.target, Target::RegKey { path }
                        if ctx.same_key(&physical(path), key))
            })
    }

    /// Whether the harvest recorded a value at or below `key` that referred to an InstallRoot or to a
    /// file of the exe set.
    pub(crate) fn snapshot_below(ctx: &ScanCtx<'_>, key: &str) -> bool {
        ctx.fp.ref_snapshot.iter().any(|entry| {
            let at = match &entry.target {
                Target::RegValue { path, .. } | Target::RegMultiSzSegment { path, .. } => path,
                _ => return false,
            };
            matches!(entry.anchor.kind, AnchorKind::Root | AnchorKind::Exe)
                && (ctx.inside_install_root(&entry.anchor.text).is_some()
                    || ctx.is_app_file(&entry.anchor.text))
                && matches!(
                    ctx.key_relation(&physical(at), key),
                    prefix::Relation::Same | prefix::Relation::Inside
                )
        })
    }

    // ---- the bounded subtree read ----------------------------------------------------------------------

    /// One value of a scanned subtree.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct ScannedValue {
        /// The key holding the value.
        pub(crate) key: String,
        /// The value name; `""` is the default value.
        pub(crate) name: String,
        /// The string of a `REG_SZ` / `REG_EXPAND_SZ` value, unexpanded.
        pub(crate) text: Option<String>,
        /// Where the string points when that is at or under an InstallRoot or at a file of the exe set.
        pub(crate) app_path: Option<String>,
        /// The value is the default value of a `command` key.
        pub(crate) command: bool,
        /// The value is a command whose data is not a string (and not empty): nobody can say what it
        /// launches.
        pub(crate) opaque_command: bool,
        /// For a command: the file of the app it launches.
        pub(crate) launch: Option<String>,
    }

    /// A key's subtree as read now, within the scan limits.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct KeyScan {
        /// The key.
        pub(crate) key: String,
        /// Its LastWriteTime.
        pub(crate) lwt: FileTime,
        /// Every value of the subtree.
        pub(crate) values: Vec<ScannedValue>,
        /// The number of keys below the key.
        pub(crate) subkeys: u32,
        /// The whole subtree was read and every string is known. `false` when something was unreadable,
        /// a limit was hit, or a string value's data is not known: such a key is never offered as a key.
        pub(crate) complete: bool,
        /// Whether `%NAME%` references in the subtree's strings are expanded ([`env_applies`]).
        expand: bool,
    }

    impl KeyScan {
        /// Reads the subtree of `key`; `None` when the key does not exist or cannot be opened.
        pub(crate) fn read(ctx: &ScanCtx<'_>, app: &AppIdentityView, key: &str) -> Option<Self> {
            let info = ctx.reg.key_info(key).ok()?;
            let mut scan = Self {
                key: key.to_owned(),
                lwt: info.lwt,
                values: Vec::new(),
                subkeys: 0,
                // A link is never read through.
                complete: !info.is_link,
                expand: env_applies(ctx, key),
            };
            if !info.is_link {
                let mut budget = ctx.limits.max_key_children;
                scan.walk(ctx, app, key, 0, &mut budget);
            }
            Some(scan)
        }

        fn walk(
            &mut self,
            ctx: &ScanCtx<'_>,
            app: &AppIdentityView,
            key: &str,
            depth: u32,
            budget: &mut usize,
        ) {
            if depth > ctx.limits.max_depth {
                self.complete = false;
                return;
            }
            let (Ok(values), Ok(subkeys)) = (ctx.reg.values(key), ctx.reg.subkeys(key)) else {
                self.complete = false;
                return;
            };
            let Some(left) = budget.checked_sub(values.len() + subkeys.len()) else {
                self.complete = false;
                return;
            };
            *budget = left;
            let in_command_key =
                prefix::leaf(key).is_some_and(|l| l.eq_ignore_ascii_case("command"));
            for value in values {
                let is_string = matches!(
                    value.data.ty,
                    purge_source::types::REG_SZ | purge_source::types::REG_EXPAND_SZ
                );
                if is_string && value.data.data_unknown {
                    self.complete = false;
                }
                let text = value.data.string();
                let command = in_command_key && value.name.is_empty();
                let launch = match (&text, command) {
                    (Some(text), true) => launch_target(ctx, text, self.expand),
                    _ => None,
                };
                let app_path = launch.clone().or_else(|| {
                    text.as_deref()
                        .and_then(|t| app_path(ctx, app, t, self.expand))
                });
                // A command that is not a string cannot be read as launching the app.
                let opaque_command = command && !is_string && value.data.len != 0;
                self.values.push(ScannedValue {
                    key: key.to_owned(),
                    name: value.name,
                    text,
                    app_path,
                    command,
                    opaque_command,
                    launch,
                });
            }
            for name in subkeys {
                self.subkeys += 1;
                let child = format!("{key}\\{name}");
                match ctx.reg.key_info(&child) {
                    Ok(info) if !info.is_link => self.walk(ctx, app, &child, depth + 1, budget),
                    _ => self.complete = false,
                }
            }
        }

        /// The file of the app that a `command` of the subtree launches, if any does.
        pub(crate) fn launch(&self) -> Option<&str> {
            self.values.iter().find_map(|v| v.launch.as_deref())
        }

        /// Whether a `command` of the subtree launches something that is not the app's: the key then
        /// serves someone else, whatever else it holds.
        pub(crate) fn foreign_command(&self) -> bool {
            self.values.iter().any(|v| {
                v.opaque_command
                    || (v.command
                        && v.launch.is_none()
                        && v.text.as_deref().is_some_and(|t| !t.trim().is_empty()))
            })
        }

        /// The first place a value of the subtree points to inside the app.
        pub(crate) fn app_ref(&self) -> Option<&str> {
            self.values.iter().find_map(|v| v.app_path.as_deref())
        }

        /// The first of `names` that is the whole data of a string value in the subtree.
        pub(crate) fn names_one_of<'n>(&self, names: &'n [String]) -> Option<&'n str> {
            self.values
                .iter()
                .filter_map(|v| v.text.as_deref())
                .find_map(|text| names.iter().find(|n| prefix::eq_ci(n, text.trim())))
                .map(String::as_str)
        }

        /// The number of subkeys and values a deletion of the key takes with it.
        pub(crate) fn child_count(&self) -> u32 {
            self.subkeys
                .saturating_add(u32::try_from(self.values.len()).unwrap_or(u32::MAX))
        }
    }

    /// Where `text` points when that is at or under an InstallRoot or at a file of the exe set. Bare exe
    /// names, inferred roots and referenced data directories do not count.
    ///
    /// With `expand` unset, a match that only holds after environment expansion does not count.
    fn app_path(
        ctx: &ScanCtx<'_>,
        app: &AppIdentityView,
        text: &str,
        expand: bool,
    ) -> Option<String> {
        app.refs
            .find_all(text)
            .into_iter()
            .filter(|m| matches!(m.anchor.kind, AnchorKind::Root | AnchorKind::Exe) && !m.name_only)
            .filter(|m| expand || !m.via_env)
            .filter_map(|m| m.path)
            .find(|path| ctx.inside_install_root(path).is_some() || ctx.is_app_file(path))
    }

    /// `%NAME%` references replaced from `env` (names upper-cased); unknown names stay as written.
    fn expand_env(text: &str, env: &BTreeMap<String, String>) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('%') else {
                out.push('%');
                rest = after;
                continue;
            };
            let name = &after[..end];
            match env.get(&name.to_uppercase()) {
                Some(value) if !name.is_empty() => {
                    out.push_str(value);
                    rest = &after[end + 1..];
                }
                // Not a variable: keep the first `%` and look again from the next one (`"%1" %*`).
                _ => {
                    out.push('%');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Lower case, `/` read as `\`, runs of `\` as one.
    fn fold_path(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            if c == '\\' || c == '/' {
                if !out.ends_with('\\') {
                    out.push('\\');
                }
            } else {
                out.extend(c.to_lowercase());
            }
        }
        out
    }

    /// The file of the app that the command line `text` launches: its **program**, the first thing on
    /// the line, is a file of the exe set or lies under an InstallRoot. A command that merely mentions
    /// the app (as an argument of another program) launches something else.
    ///
    /// The path is returned in folded form (lower case), which is enough for prefix tests and for
    /// probing the file system.
    ///
    /// `%NAME%` references are expanded from the scan's environment only with `expand` set
    /// ([`env_applies`]); otherwise they stay as written and match nothing.
    pub(crate) fn launch_target(ctx: &ScanCtx<'_>, text: &str, expand: bool) -> Option<String> {
        let expanded = if expand {
            expand_env(text, ctx.env)
        } else {
            text.to_owned()
        };
        let line = expanded.trim_start();
        let (program, quoted) = match line.strip_prefix('"') {
            Some(rest) => (rest.split('"').next().unwrap_or(""), true),
            None => (line, false),
        };
        let folded = fold_path(program.trim());
        if folded.is_empty() || folded.split('\\').any(|seg| seg == "..") {
            return None;
        }
        let fp = ctx.fp;
        let ends = |rest: &str| {
            rest.is_empty()
                || (!quoted && rest.starts_with(|c: char| c.is_whitespace() || c == ','))
        };
        let files = fp
            .exes
            .iter()
            .map(|e| &e.path)
            .chain(fp.outside_root_files.iter().map(|f| &f.path));
        for file in files {
            let file = fold_path(file);
            if folded.strip_prefix(file.as_str()).is_some_and(ends) {
                return Some(file);
            }
        }
        let mut roots: Vec<&Root> = fp
            .roots
            .iter()
            .filter(|r| r.kind == RootKind::InstallRoot)
            .collect();
        roots.sort_by_key(|r| std::cmp::Reverse(prefix::depth(&r.path)));
        for root in roots {
            let root = fold_path(root.path.trim_end_matches(prefix::SEP));
            let below = folded
                .strip_prefix(root.as_str())
                .is_some_and(|rest| rest.len() > 1 && rest.starts_with('\\'));
            if below {
                let end = if quoted {
                    folded.len()
                } else {
                    program_end(&folded, root.len())
                };
                return Some(folded[..end].trim_end().to_owned());
            }
        }
        None
    }

    /// Where the program of an unquoted command line ends: after the first executable extension that is
    /// followed by white space or the end, searched from `from`; the whole line when there is none.
    fn program_end(line: &str, from: usize) -> usize {
        const EXTENSIONS: [&str; 4] = [".exe", ".com", ".bat", ".cmd"];
        EXTENSIONS
            .iter()
            .flat_map(|ext| {
                line[from..]
                    .match_indices(ext)
                    .map(move |(at, hit)| from + at + hit.len())
            })
            .filter(|&end| {
                line[end..]
                    .chars()
                    .next()
                    .is_none_or(|c| c.is_whitespace() || c == ',')
            })
            .min()
            .unwrap_or(line.len())
    }

    // ---- candidates ------------------------------------------------------------------------------------

    /// Starts the `DeleteKey` candidate for the key of `scan`, with every kind of evidence that holds for
    /// this exact key: an Inno key-create record, `ProvenOwnedSkeleton`, harvested tokens in the key's
    /// own name and, when the caller established one, a `ChainedRef` to `chain` (the anchor's tier and
    /// its text). The common blockers, the child count and the time window are set.
    ///
    /// `None` when the key may not be offered as a key ([`key_offerable`]), when its subtree was not read
    /// completely, or when no Tier A or Tier B evidence holds.
    pub(crate) fn key_candidate<'c>(
        ctx: &'c ScanCtx<'_>,
        scanner: &str,
        scan: &KeyScan,
        category: Category,
        chain: Option<(Tier, &str)>,
    ) -> Option<CandidateBuilder<'c>> {
        if !scan.complete || !key_offerable(ctx, &scan.key) {
            return None;
        }
        let target = Target::RegKey {
            path: scan.key.clone(),
        };
        let mut builder = ctx.candidate(scanner, target, Action::DeleteKey, category);
        builder.installer_manifest();
        builder.proven_owned_skeleton();
        for token in &ctx.fp.tokens {
            builder.harvested_token(&token.token);
        }
        if let Some((tier, anchor)) = chain {
            builder.chained_ref(tier, anchor);
        }
        if !builder.has_tier_ab_evidence() {
            return None;
        }
        builder.time_window(scan.lwt);
        builder.child_count(scan.child_count());
        builder.common_blockers();
        Some(builder)
    }

    /// The value-level candidates of a subtree whose key is not offered: every value that points into
    /// the app, with `InPreUninstallRefSnapshot`, an Inno value record, `PointsIntoInstallRoot` and
    /// `DanglingRef` as far as each holds.
    pub(crate) fn value_candidates(
        ctx: &ScanCtx<'_>,
        scanner: &str,
        scan: &KeyScan,
        category: Category,
    ) -> Vec<Candidate> {
        let mut out = Vec::new();
        for value in &scan.values {
            let Some(path) = &value.app_path else {
                continue;
            };
            let target = Target::RegValue {
                path: value.key.clone(),
                name: value.name.clone(),
            };
            let mut builder = ctx.candidate(scanner, target, Action::DeleteValue, category);
            builder.in_ref_snapshot();
            builder.installer_manifest();
            builder.points_into_install_root(path);
            if let Some(dangling) = ctx.dangling(path) {
                builder.dangling_ref(&dangling);
            }
            if builder.has_positive_evidence() {
                builder.common_blockers();
                out.push(builder.build());
            }
        }
        out
    }

    /// The `DeleteKey` candidate for a structural-looking parent (a `shell` key) that may only ever go
    /// as a proven owned skeleton.
    pub(crate) fn skeleton_candidate(
        ctx: &ScanCtx<'_>,
        scanner: &str,
        key: &str,
        category: Category,
    ) -> Option<Candidate> {
        if !key_offerable(ctx, key) {
            return None;
        }
        let target = Target::RegKey {
            path: key.to_owned(),
        };
        let mut builder = ctx.candidate(scanner, target, Action::DeleteKey, category);
        if !builder.proven_owned_skeleton() {
            return None;
        }
        builder.installer_manifest();
        // Value-free by proof; what is left below it are empty keys.
        if let Ok(info) = ctx.reg.key_info(key) {
            builder.child_count(info.n_subkeys);
        }
        builder.common_blockers();
        Some(builder.build())
    }
}
