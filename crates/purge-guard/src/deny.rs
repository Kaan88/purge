//! The hard deny-list (ENGINE_PLAN.md §5.10): locations that are never removed, whatever the evidence.
//!
//! # Rule model
//!
//! A [`Rule`] is a pattern (see the `pattern` submodule for the syntax) with an [`Annotation`]:
//!
//! | | the item itself | its descendants | its ancestors | values directly in the key |
//! |---|---|---|---|---|
//! | **\[S\]** subtree | denied | denied | denied | denied |
//! | **\[E\]** exact | denied | allowed | allowed | allowed, unless the rule protects them |
//! | **\[E+A\]** exact and ancestors | denied | allowed | denied | as \[E\] |
//!
//! Removing an ancestor removes the item, so an \[S\] rule also denies the ancestors of its item. For a
//! pattern with wildcards that holds only for the ancestors above the first wildcard: `FileExts\*\UserChoice`
//! \[S\] denies `FileExts` but not `FileExts\.txt`, which may hold nothing protected.
//!
//! The rules are compiled from three sources: the built-in table of §5.10 (file rules are expanded from
//! the [`GuardEnv`], never from the process environment), the dynamic facts in the `GuardEnv` (sync roots,
//! other apps' roots, protected and Purge directories), and the data rules of `kb/deny.json`
//! ([`DataRule`]), which are embedded at build time.
//!
//! # Checking
//!
//! [`check`] canonicalises the target itself ([`crate::canon`]); a target that does not canonicalise is
//! denied with a `canon.*` rule name. It fails closed: an incomplete `GuardEnv`, an unparsable rule file,
//! an unbound `HKCU`, a hive that is not loaded and an unresolved 8.3 name are all denials. Service, task,
//! firewall-rule and package targets are not locations and always pass.
//!
//! The directories of the `GuardEnv` are canonicalised before any rule is compiled from them
//! ([`GuardEnv::normalised`]), so a fact spelled `C:/Windows` protects what `C:\Windows` does; one that
//! cannot be canonicalised makes the list deny everything.
//!
//! [`Exemptions`] carries what the candidate's evidence has earned. The two exemptions of §5.10 are
//! `ProvenOwnedSkeleton` for the `shell`/`shellex` roots under Classes, and the `Environment` segment edit
//! under `Session Manager`. Two more inputs are facts rather than permissions: a Tier A shortcut or folder
//! below the all-users Start Menu `Programs` folder (the carve-out in the `ProgramData\Microsoft` rule),
//! and "8.3 names have been resolved".
//!
//! Two exceptions need no exemption because the rule text itself excludes them: a single
//! `%WINDIR%\Prefetch\<name>.pf` file, and keys of an event source
//! (`HKLM\SYSTEM\<set>\Services\EventLog\<log>\<source>`).
//!
//! # M1b (C-GUARD)
//!
//! The Windows Installer database (`...\CurrentVersion\Installer`, `HKU\<sid>\Software\Microsoft\
//! Installer`, `<Classes>\Installer`) is a subtree rule (`reg.installer`). It lets a target through only
//! in the eight shapes of C-GUARD for a product in [`Exemptions::gone_msi_products`], and in the two Burn
//! dependency shapes for a name in [`Exemptions::gone_burn`] (`installer_shape`). Package Cache entries
//! are denied (`fs.package-cache`) unless they lie in an entry of [`Exemptions::gone_cache_dirs`] that is a
//! direct child of a Package Cache root. Empty lists close both exemptions.
//!
//! Under `HKLM\SYSTEM`, which stays denied as a whole, the rules `fw.registry-direct`,
//! `svc.registry-direct` and `reg.eventlog-log` name what a target is before `reg.hklm.system` does.
//! Typed objects (services, tasks, firewall rules) are judged by [`check_object`], not by the location
//! rules.

use purge_model::{Blocker, Target, View};
use serde::{Deserialize, Serialize};

use crate::canon::{CanonKey, GuardEnv, canon_key, canon_path};
use crate::prefix::fold;

mod objects;
pub(crate) mod pattern;
mod rules;
mod shared;
#[cfg(test)]
mod tests;

pub use objects::{ObjectGuardFacts, check_object};
pub use rules::{SharedIid, SharedIids, shared_iids};
pub use shared::{SharedComponent, SharedComponents, shared_components};

/// The names of the deny rules added in M1b (C-GUARD), as reported in [`Blocker::DenyListed`]. A scanner
/// that blocks with one of them from its own facts (`com.system-class` from the baseline, say) uses these
/// constants, so that one name is never spelled two ways.
pub mod ids {
    /// A service of a driver type (or of a type that could not be read).
    pub const SYS_DRIVER: &str = "sys.driver";
    /// A per-user service template or instance.
    pub const SYS_SERVICE_PERUSER: &str = "sys.service.peruser";
    /// A service whose program is under `%SystemRoot%`.
    pub const SYS_SERVICE_WINDOWS: &str = "sys.service.windows";
    /// A service already marked for deletion.
    pub const SYS_SERVICE_MARKED: &str = "sys.service.marked";
    /// A task in one of Windows' folders, or whose program is under `%SystemRoot%`.
    pub const SYS_TASK_WINDOWS: &str = "sys.task.windows";
    /// A firewall rule bound to an AppX package or AppContainer.
    pub const FW_PACKAGE_BOUND: &str = "fw.package-bound";
    /// A firewall rule whose name is a resource reference (`@...`): Windows' own rule groups.
    pub const FW_RESOURCE_NAME: &str = "fw.resource-name";
    /// The firewall policy store under `HKLM\SOFTWARE\Policies`.
    pub const FW_POLICY_STORE: &str = "fw.policy-store";
    /// Any registry target in the firewall's own store: rules are removed only as `Target::FirewallRule`.
    pub const FW_REGISTRY_DIRECT: &str = "fw.registry-direct";
    /// A service's key or one of its structural subkeys: services are removed only as `Target::Service`.
    pub const SVC_REGISTRY_DIRECT: &str = "svc.registry-direct";
    /// The Task Scheduler's registry cache and task directories: tasks are removed only as
    /// `Target::Task`.
    pub const TASK_REGISTRY_DIRECT: &str = "task.registry-direct";
    /// An interface listed in `kb/shared-iids.json`.
    pub const COM_SHARED_IID: &str = "com.shared-iid";
    /// A proxy/stub CLSID listed in `kb/shared-iids.json` (`shared_proxy_clsids`): never an owner.
    pub const COM_SHARED_PROXY: &str = "com.shared-proxy";
    /// A CLSID, AppID, TypeLib or Interface present in the Windows baseline. Not a location rule (the
    /// guard has no baseline): the COM scanners report it.
    pub const COM_SYSTEM_CLASS: &str = "com.system-class";
    /// A component key of the Installer database; only a gone product's value in it is offered.
    pub const MSI_COMPONENT_FOREIGN: &str = "msi.component-foreign";
    /// The Windows Installer database.
    pub const REG_INSTALLER: &str = "reg.installer";
    /// A `SharedDLLs` key itself.
    pub const REG_SHAREDDLLS: &str = "reg.shareddlls";
    /// An event log key itself; only its source keys are offered.
    pub const REG_EVENTLOG_LOG: &str = "reg.eventlog-log";
    /// The `Tracing` key itself.
    pub const REG_TRACING_ROOT: &str = "reg.tracing-root";
    /// A WER report directory itself.
    pub const FS_WER_ROOT: &str = "fs.wer-root";
    /// A Package Cache root, or an entry in it that no exemption opens (the plan's
    /// `fs.package-cache-root`; the M1a id is kept).
    pub const FS_PACKAGE_CACHE: &str = "fs.package-cache";
}

use pattern::{
    KeyBase, Rel, Seg, literal, parse_fs_pattern, parse_key_pattern, relate, split_fold,
};

/// How far a rule reaches from the item it names. See the module documentation for the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Annotation {
    /// **\[S\]**: the item and its whole subtree.
    #[serde(rename = "S")]
    Subtree,
    /// **\[E\]**: the item only.
    #[serde(rename = "E")]
    Exact,
    /// **\[E+A\]**: the item and every ancestor.
    #[serde(rename = "E+A")]
    ExactAndAncestors,
}

impl Annotation {
    /// The annotation as written in ENGINE_PLAN.md: `S`, `E` or `E+A`.
    pub fn as_str(self) -> &'static str {
        match self {
            Annotation::Subtree => "S",
            Annotation::Exact => "E",
            Annotation::ExactAndAncestors => "E+A",
        }
    }
}

/// What a data rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataRuleKind {
    /// A file or directory path.
    Path,
    /// A registry key.
    Key,
}

/// One entry of `kb/deny.json`: a deny rule kept as data rather than code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataRule {
    /// The rule name reported in [`Blocker::DenyListed`]. Prefixed with `kb.` when compiled.
    pub id: String,
    /// Path or key.
    pub kind: DataRuleKind,
    /// The reach of the rule.
    pub annotation: Annotation,
    /// The pattern (syntax: see the `pattern` submodule; briefly, `%ProgramFiles%\X`, `*:\X`,
    /// `HKLM\SOFTWARE\X`, `HKU\*\SOFTWARE\X`, `*\SOFTWARE\X`, `HKCR\X`, with `*` globs per segment).
    pub pattern: String,
    /// For an \[E\] or \[E+A\] key rule: also deny values directly in the key.
    #[serde(default)]
    pub values: bool,
    /// For a key rule: restrict it to one WOW64 view. Absent means both.
    #[serde(default)]
    pub view: Option<View>,
    /// Why the location is protected.
    pub why: String,
}

/// The data rules embedded from `kb/deny.json`.
pub fn kb_rules() -> Result<Vec<DataRule>, serde_json::Error> {
    serde_json::from_str(include_str!("../../../kb/deny.json"))
}

/// What the candidate's evidence has earned, and what the caller has already done.
///
/// The three lists (M1b) are filled by the plan's decide step from the fingerprint and a fresh query of
/// Windows Installer, never from a scanner's candidate facts. Each is empty by default, and an empty list
/// opens nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Exemptions<'a> {
    /// The key carries `ProvenOwnedSkeleton` evidence: lifts the rules on the `shell` / `shellex` roots
    /// under the Classes shell objects (exact key only).
    pub proven_owned_skeleton: bool,
    /// The action is a segment edit of a value in `HKLM\SYSTEM\<current set>\Control\Session Manager\
    /// Environment` (PATH and the like). Lifts the `HKLM\SYSTEM` rule for exactly that target.
    pub environment_segment_edit: bool,
    /// The candidate has Tier A evidence: lifts the `ProgramData\Microsoft` rule for items strictly below
    /// the all-users `Start Menu\Programs` folder. The Start Menu roots and Windows' own entries stay
    /// denied by their own rules.
    pub tier_a_start_menu_entry: bool,
    /// The path has had its 8.3 names resolved (or was read from the file system in long form). Without
    /// this, a path with a segment that looks like a short name is denied, because the lexical tests
    /// cannot see what it aliases.
    pub long_names_resolved: bool,
    /// The target is one value (a whole-value delete, never a key, a segment or an edit) and the
    /// candidate's admin-trust evidence ties that value's data to the app before the uninstall (R2a
    /// S10). Lifts `com.shared-iid` and `com.shared-proxy` for exactly that value; the shared keys
    /// themselves stay denied. Such a value was last written for the app (its data named the app's file
    /// or one of its anchors): any other product that shares the interface already points at what the
    /// app's uninstall removed, so removing the value takes nothing from it that still works.
    pub shared_com_value: bool,
    /// Bundle ids and provider keys of Burn bundles and packages that are gone. Lets through, under
    /// `reg.installer`, exactly the keys `<Classes>\Installer\Dependencies\<P>` with `P` listed and
    /// `<Classes>\Installer\Dependencies\<P>\Dependents\<B>` with `B` listed, where `<Classes>` is
    /// `HKLM\SOFTWARE\Classes` or a user's Classes. Whole segment, case-insensitive.
    pub gone_burn: &'a [String],
    /// Packed product codes (32 hex digits) unknown to Windows Installer in every context. Lets through,
    /// under `reg.installer`, exactly the eight shapes of C-GUARD (see `installer_shape`). An entry that
    /// is not 32 hex digits is ignored.
    pub gone_msi_products: &'a [String],
    /// Canonical Package Cache directories of gone products and bundles. Lets a path through the
    /// `fs.package-cache` rule when it equals or lies inside an entry that is a direct child of a Package
    /// Cache root; any other entry (a root itself, a deeper directory, anything outside) is ignored.
    pub gone_cache_dirs: &'a [String],
}

/// A carve-out a rule honours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exempt {
    Skeleton,
    StartMenu,
    Prefetch,
    /// The Installer database rule: lifted for the shapes of `installer_shape`.
    GoneInstaller,
    /// The Package Cache subtree rule: lifted inside a listed direct child of a cache root.
    GoneCache,
    /// The shared COM rules (`com.shared-iid`, `com.shared-proxy`): lifted for a single value at or below
    /// the shared key when [`Exemptions::shared_com_value`] is set; never for a key.
    SharedComValue,
}

#[derive(Debug, Clone)]
enum Matcher {
    Fs(Vec<Seg>),
    /// The path ends with these segments, at any depth (`steamapps`).
    FsSuffix(Vec<Seg>),
    Key(KeyBase, Vec<Seg>),
}

/// One compiled deny rule.
#[derive(Debug, Clone)]
pub struct Rule {
    id: String,
    annotation: Annotation,
    pattern: String,
    why: String,
    matcher: Matcher,
    protect_values: bool,
    view: Option<View>,
    exempt: Option<Exempt>,
}

impl Rule {
    /// The rule name reported in [`Blocker::DenyListed`].
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The reach of the rule.
    pub fn annotation(&self) -> Annotation {
        self.annotation
    }

    /// The pattern as written (before expansion from the `GuardEnv`).
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Why the location is protected.
    pub fn why(&self) -> &str {
        &self.why
    }

    /// Whether this is a registry rule (otherwise a file rule).
    pub fn is_registry(&self) -> bool {
        matches!(self.matcher, Matcher::Key(..))
    }

    fn new(id: &str, annotation: Annotation, pattern: &str, why: &str, matcher: Matcher) -> Rule {
        Rule {
            id: id.to_owned(),
            annotation,
            pattern: pattern.to_owned(),
            why: why.to_owned(),
            matcher,
            protect_values: false,
            view: None,
            exempt: None,
        }
    }

    /// File rules for a pattern: one per directory its token expands to.
    fn fs(
        id: &str,
        annotation: Annotation,
        pattern: &str,
        why: &str,
        env: &GuardEnv,
    ) -> Result<Vec<Rule>, String> {
        Ok(parse_fs_pattern(pattern, env)?
            .into_iter()
            .map(|segs| Rule::new(id, annotation, pattern, why, Matcher::Fs(segs)))
            .collect())
    }

    /// A file rule for a concrete directory from the `GuardEnv`; `None` when the path is blank.
    fn fs_literal(id: &str, annotation: Annotation, path: &str, why: &str) -> Option<Rule> {
        let segs = literal(path);
        (!segs.is_empty()).then(|| Rule::new(id, annotation, path, why, Matcher::Fs(segs)))
    }

    fn key(id: &str, annotation: Annotation, pattern: &str, why: &str) -> Result<Rule, String> {
        let (base, segs) = parse_key_pattern(pattern)?;
        Ok(Rule::new(
            id,
            annotation,
            pattern,
            why,
            Matcher::Key(base, segs),
        ))
    }

    fn with_values(mut self, protect: bool) -> Rule {
        self.protect_values = protect;
        self
    }

    fn with_exempt(mut self, exempt: Exempt) -> Rule {
        self.exempt = Some(exempt);
        self
    }

    /// Whether a target standing in relation `rel` to the rule's item is denied. `value`: the target is a
    /// value (or a segment of one) in the related key, not the key or path itself.
    fn denies(&self, rel: Rel, value: bool) -> bool {
        use Annotation::*;
        match (self.annotation, rel) {
            (Subtree, Rel::Exact | Rel::Inside) => true,
            (Subtree, Rel::Ancestor { literal }) => literal && !value,
            (Exact | ExactAndAncestors, Rel::Exact) => !value || self.protect_values,
            (ExactAndAncestors, Rel::Ancestor { .. }) => !value,
            (Exact, Rel::Ancestor { .. }) | (Exact | ExactAndAncestors, Rel::Inside) => false,
        }
    }
}

/// A canonical registry key in the shapes the key patterns match against.
pub(crate) struct RegLogical {
    pub(crate) key: CanonKey,
    machine: bool,
    /// Folded path below the hive root, view-agnostic; a user's Classes hive reads `software\classes\..`.
    full: Vec<String>,
    /// Folded path below the Classes root, when the key is under one.
    classes: Option<Vec<String>>,
}

impl RegLogical {
    pub(crate) fn new(key: CanonKey) -> RegLogical {
        let segs = split_fold(&key.path);
        let (machine, full, classes) = match &key.hive {
            purge_model::Hive::Hklm => {
                let classes = (segs.len() >= 2 && segs[0] == "software" && segs[1] == "classes")
                    .then(|| segs[2..].to_vec());
                (true, segs, classes)
            }
            purge_model::Hive::Hku(_) => (false, segs, None),
            purge_model::Hive::HkuClasses(_) => {
                let mut full = vec!["software".to_owned(), "classes".to_owned()];
                full.extend(segs.iter().cloned());
                (false, full, Some(segs))
            }
        };
        RegLogical {
            key,
            machine,
            full,
            classes,
        }
    }

    /// The segments a pattern with this base is matched against, if the base applies to this key.
    pub(crate) fn segs_for(&self, base: KeyBase) -> Option<&[String]> {
        match base {
            KeyBase::Hklm => self.machine.then_some(&self.full[..]),
            KeyBase::Hku => (!self.machine).then_some(&self.full[..]),
            KeyBase::Any => Some(&self.full[..]),
            KeyBase::Classes => self.classes.as_deref(),
        }
    }
}

/// The registry key of a registry target.
pub(crate) fn key_of(target: &Target) -> Option<&str> {
    match target {
        Target::RegKey { path }
        | Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => Some(path),
        _ => None,
    }
}

/// A "no root may live here" pattern: the rule name and the location.
pub(crate) type RootOnly = (&'static str, Vec<Seg>);

/// The compiled deny-list for one `GuardEnv`. Compile once per scan and reuse; [`check`] is the one-shot
/// form.
#[derive(Debug, Clone)]
pub struct DenyList {
    env: GuardEnv,
    /// `env` with every directory canonicalised ([`GuardEnv::normalised`]); what the rules were compiled
    /// from and what targets are matched against.
    norm: GuardEnv,
    rules: Vec<Rule>,
    /// The rules below `HKLM\SYSTEM` that name a target before the blanket `reg.hklm.system` (M1b).
    system_rules: Vec<Rule>,
    /// Extra "cannot be a root" patterns for [`DenyList::root_rejection`].
    root_only: Vec<RootOnly>,
    /// Set when the list could not be built; every location is then denied.
    invalid: Option<String>,
}

impl DenyList {
    /// Built-in rules, the dynamic rules of `env`, and the embedded `kb/deny.json`.
    pub fn compile(env: &GuardEnv) -> DenyList {
        match kb_rules() {
            Ok(data) => DenyList::with_data(env, &data),
            Err(e) => DenyList::broken(env, format!("kb/deny.json: {e}")),
        }
    }

    /// Built-in and dynamic rules plus the given data rules (instead of the embedded ones).
    pub fn with_data(env: &GuardEnv, data: &[DataRule]) -> DenyList {
        let missing = env.missing();
        if !missing.is_empty() {
            return DenyList::broken(env, format!("GuardEnv lacks {}", missing.join(", ")));
        }
        // Rules are compiled from the canonical spelling of the facts: a directory that arrives as
        // `C:/Windows` or `C:\Windows\` must protect what `C:\Windows` protects.
        let norm = match env.normalised() {
            Ok(norm) => norm,
            Err(e) => return DenyList::broken(env, e),
        };
        type Built = (Vec<Rule>, Vec<Rule>, Vec<RootOnly>);
        let build = |env: &GuardEnv| -> Result<Built, String> {
            let mut all = Vec::new();
            for rule in data {
                let id = format!("kb.{}", rule.id);
                match rule.kind {
                    DataRuleKind::Path => {
                        all.extend(Rule::fs(
                            &id,
                            rule.annotation,
                            &rule.pattern,
                            &rule.why,
                            env,
                        )?);
                    }
                    DataRuleKind::Key => {
                        let mut compiled =
                            Rule::key(&id, rule.annotation, &rule.pattern, &rule.why)?
                                .with_values(rule.values);
                        compiled.view = rule.view;
                        all.push(compiled);
                    }
                }
            }
            all.extend(rules::builtin(env)?);
            Ok((all, rules::system()?, rules::root_only(env)?))
        };
        match build(&norm) {
            Ok((rules, system_rules, root_only)) => DenyList {
                env: env.clone(),
                norm,
                rules,
                system_rules,
                root_only,
                invalid: None,
            },
            Err(e) => DenyList::broken(env, e),
        }
    }

    fn broken(env: &GuardEnv, reason: String) -> DenyList {
        DenyList {
            env: env.clone(),
            norm: env.clone(),
            rules: Vec::new(),
            system_rules: Vec::new(),
            root_only: Vec::new(),
            invalid: Some(reason),
        }
    }

    /// Why the list denies everything, when it could not be built.
    pub fn invalid(&self) -> Option<&str> {
        self.invalid.as_deref()
    }

    /// Every compiled rule (file patterns appear once per directory they expand to).
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The `GuardEnv` the list was compiled for.
    pub fn env(&self) -> &GuardEnv {
        &self.env
    }

    /// The blocker for a denied target, or `None` when no rule applies.
    pub fn check(&self, target: &Target, exemptions: &Exemptions<'_>) -> Option<Blocker> {
        self.denying_rule(target, exemptions)
            .map(|rule| Blocker::DenyListed { rule })
    }

    /// The name of the rule that denies the target, if any.
    pub fn denying_rule(&self, target: &Target, exemptions: &Exemptions<'_>) -> Option<String> {
        let location = matches!(target, Target::Path { .. }) || target.is_registry();
        if !location {
            return None;
        }
        if self.invalid.is_some() {
            return Some("guard.unavailable".to_owned());
        }
        match target {
            Target::Path { path } => self.check_path(path, exemptions, false),
            other => self.check_key(other, key_of(other)?, exemptions),
        }
    }

    /// [`check_object`] with the Windows directory of this list's `GuardEnv` added to the lexical
    /// `%SystemRoot%` forms, so that a Windows installed elsewhere than `<drive>:\Windows` is still
    /// recognised. A list that could not be built blocks every object (`guard.unavailable`). Callers that
    /// hold a `DenyList` (the scanners, the executor gate) use this form.
    pub fn check_object(
        &self,
        kind: purge_model::ObjectKind,
        facts: &ObjectGuardFacts<'_>,
    ) -> Option<Blocker> {
        if self.invalid.is_some() {
            return Some(Blocker::DenyListed {
                rule: "guard.unavailable".to_owned(),
            });
        }
        objects::check_object_in(kind, facts, Some(&split_fold(&self.norm.windir)))
    }

    /// `for_root`: the question is whether a root may live at `path` ([`DenyList::root_rejection`]). The
    /// Package Cache subtree rule is then skipped and left to the `root.package-cache` pattern, which
    /// names the refusal the way M1a did.
    fn check_path(&self, path: &str, ex: &Exemptions<'_>, for_root: bool) -> Option<String> {
        let segs = match self.path_segments(path, ex.long_names_resolved) {
            Ok(segs) => segs,
            Err(rule) => return Some(rule),
        };
        if segs.len() <= 1 {
            return Some("fs.drive-root".to_owned());
        }
        let prefetch_file = {
            let windir = split_fold(&self.norm.windir);
            segs.len() == windir.len() + 2
                && segs.starts_with(&windir)
                && segs[windir.len()] == "prefetch"
                && is_prefetch_trace(&segs[segs.len() - 1])
        };
        let start_menu_entry = ex.tier_a_start_menu_entry && {
            let mut programs = split_fold(&self.norm.program_data);
            programs.extend(["microsoft", "windows", "start menu", "programs"].map(String::from));
            segs.len() > programs.len() && segs.starts_with(&programs)
        };
        let gone_cache = !for_root && self.in_gone_cache_dir(&segs, ex);
        first_hit(self.rules.iter().filter_map(|rule| {
            if for_root && rule.exempt == Some(Exempt::GoneCache) {
                return None;
            }
            let lifted = match rule.exempt {
                Some(Exempt::Prefetch) => prefetch_file,
                Some(Exempt::StartMenu) => start_menu_entry,
                Some(Exempt::GoneCache) => gone_cache,
                _ => false,
            };
            let rel = match &rule.matcher {
                Matcher::Fs(pattern) => relate(pattern, &segs),
                Matcher::FsSuffix(pattern) => (segs.len() >= pattern.len())
                    .then(|| relate(pattern, &segs[segs.len() - pattern.len()..]))
                    .flatten(),
                Matcher::Key(..) => None,
            };
            rel.filter(|rel| !lifted && rule.denies(*rel, false))
                .map(|rel| (rule, rel))
        }))
    }

    /// Whether the path (the folded segments of its canonical form) equals or lies inside an entry of
    /// `gone_cache_dirs` that is a direct child of a Package Cache root. An entry that does not
    /// canonicalise, or that has a segment shaped like a short name, is ignored.
    fn in_gone_cache_dir(&self, segs: &[String], ex: &Exemptions<'_>) -> bool {
        ex.gone_cache_dirs.iter().any(|entry| {
            let Ok(canon) = canon_path(entry, &self.norm, None) else {
                return false;
            };
            if canon.needs_long_name {
                return false;
            }
            let entry = split_fold(&canon.path);
            let direct_child = self.rules.iter().any(|rule| match &rule.matcher {
                Matcher::Fs(root) if rule.exempt == Some(Exempt::GoneCache) => {
                    entry.len() == root.len() + 1 && relate(root, &entry) == Some(Rel::Inside)
                }
                _ => false,
            });
            direct_child && segs.starts_with(&entry)
        })
    }

    /// The folded segments of the canonical form of `path`, or the `canon.*` rule that refuses it.
    fn path_segments(&self, path: &str, long_names_resolved: bool) -> Result<Vec<String>, String> {
        let canon =
            canon_path(path, &self.norm, None).map_err(|e| format!("canon.{}", e.code()))?;
        if canon.needs_long_name && !long_names_resolved {
            return Err("canon.short-name-unresolved".to_owned());
        }
        Ok(split_fold(&canon.path))
    }

    fn check_key(&self, target: &Target, key_path: &str, ex: &Exemptions<'_>) -> Option<String> {
        let key = match canon_key(key_path, None, &self.env, None) {
            Ok(key) => key,
            Err(e) => return Some(format!("canon.{}", e.code())),
        };
        if let Some(sid) = key.hive.sid() {
            if matches!(sid, ".DEFAULT" | "S-1-5-18" | "S-1-5-19" | "S-1-5-20") {
                return Some("reg.hku.system-account".to_owned());
            }
            if !self
                .env
                .loaded_sids
                .iter()
                .any(|s| s.eq_ignore_ascii_case(sid))
            {
                return Some("reg.hku.not-loaded".to_owned());
            }
        }
        let is_key = matches!(target, Target::RegKey { .. });
        let logical = RegLogical::new(key);
        if logical.machine && logical.full.first().is_some_and(|s| s != "software") {
            let full = &logical.full;
            let system = full[0] == "system";
            let current_set = self.env.control_set_name().map(|s| fold(&s));
            let environment_edit = ex.environment_segment_edit
                && matches!(target, Target::RegMultiSzSegment { .. })
                && full.len() == 5
                && system
                && Some(&full[1]) == current_set.as_ref()
                && full[2..] == ["control", "session manager", "environment"];
            // Only in the current control set: the others are boot fallbacks and are never edited.
            let event_source = system
                && full.len() >= 6
                && Some(&full[1]) == current_set.as_ref()
                && full[2..4] == ["services", "eventlog"];
            if !(environment_edit || event_source) {
                // Under SYSTEM, the M1b rules name what the target is; `reg.hklm.system` denies the rest,
                // the ancestors of their items included.
                if system {
                    let named = first_hit(self.system_rules.iter().filter_map(|rule| {
                        let Matcher::Key(KeyBase::Hklm, pattern) = &rule.matcher else {
                            return None;
                        };
                        let rel = relate(pattern, full)?;
                        (matches!(rel, Rel::Exact | Rel::Inside) && rule.denies(rel, !is_key))
                            .then_some((rule, rel))
                    }));
                    if named.is_some() {
                        return named;
                    }
                }
                let rule = if system {
                    "reg.hklm.system"
                } else {
                    "reg.hklm.non-software"
                };
                return Some(rule.to_owned());
            }
        }
        // A user's `Environment` key is a value container, so single values in it pass the rules below.
        // The variables Windows itself defines there are not any app's to delete whole (a PATH entry is
        // removed as a segment, never as the value).
        if let Target::RegValue { name, .. } = target {
            let core = CORE_ENVIRONMENT_VALUES
                .iter()
                .any(|core| name.eq_ignore_ascii_case(core));
            if core && !logical.machine && logical.full == ["environment"] {
                return Some("reg.environment.core-value".to_owned());
            }
        }
        let installer_lift = installer_shape(&logical, target, ex);
        first_hit(self.rules.iter().filter_map(|rule| {
            let Matcher::Key(base, pattern) = &rule.matcher else {
                return None;
            };
            if rule.view.is_some_and(|view| view != logical.key.view) {
                return None;
            }
            let rel = logical
                .segs_for(*base)
                .and_then(|segs| relate(pattern, segs))?;
            let lifted = match rule.exempt {
                Some(Exempt::Skeleton) => ex.proven_owned_skeleton && is_key && rel == Rel::Exact,
                Some(Exempt::GoneInstaller) => installer_lift,
                Some(Exempt::SharedComValue) => {
                    ex.shared_com_value
                        && matches!(target, Target::RegValue { .. })
                        && matches!(rel, Rel::Exact | Rel::Inside)
                }
                _ => false,
            };
            (!lifted && rule.denies(rel, !is_key)).then_some((rule, rel))
        }))
    }

    /// Why `path` cannot be the root of an app (§5.2 `validate_root`), as far as lexical facts go: it is
    /// denied as a target, or it is at or below a location where no root may live (a Package Cache, the
    /// InstallShield information folder, a user-content known folder). `None` means the guard has no
    /// objection; the harvest still applies its own checks (other apps' anchors, vendor folders).
    pub fn root_rejection(&self, path: &str, long_names_resolved: bool) -> Option<String> {
        let ex = Exemptions {
            long_names_resolved,
            ..Exemptions::default()
        };
        let denied = if self.invalid.is_some() {
            Some("guard.unavailable".to_owned())
        } else {
            self.check_path(path, &ex, true)
        };
        if let Some(rule) = denied {
            return Some(rule);
        }
        let segs = self.path_segments(path, long_names_resolved).ok()?;
        self.root_only
            .iter()
            .find(|(_, pattern)| matches!(relate(pattern, &segs), Some(Rel::Exact | Rel::Inside)))
            .map(|(id, _)| (*id).to_owned())
    }
}

/// The folded segments of `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer` below the hive.
const MSI_ROOT: [&str; 5] = [
    "software",
    "microsoft",
    "windows",
    "currentversion",
    "installer",
];

/// Whether the target is one of the shapes the `reg.installer` rule lets through for the exemption lists
/// (C-GUARD); every other target under the rule stays denied. All comparisons are on whole folded
/// segments of the canonical key, which is view-agnostic and spells a user's Classes one way, so the
/// WOW64 spellings and both spellings of a user's Classes give the same answer.
///
/// With `P` a listed packed product code (`gone_msi_products`):
/// 1. `HKLM\...\Installer\UserData\<sid>\Products\<P>` (key);
/// 2. `HKLM\SOFTWARE\Classes\Installer\Products\<P>` (key);
/// 3. `HKU\<sid>\Software\Microsoft\Installer\Products\<P>` (key);
/// 4. `HKLM\...\Installer\UpgradeCodes\<U>`, the value named `<P>`;
/// 5. `HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\<U>`, the value named `<P>`;
/// 6. `HKLM\...\Installer\UserData\<sid>\Components\<C>`, the value named `<P>`;
/// 7. `HKLM\SOFTWARE\Classes\Installer\Features\<P>` (key);
/// 8. a named value of `HKLM\...\Installer\Folders`, while at least one product is listed. The store is
///    path-keyed (C-PATHSTORES): a value's name is a directory, which only the scanner can match against
///    the app's roots; the guard ties it to no product.
///
/// With a listed Burn name (`gone_burn`), in `HKLM\SOFTWARE\Classes` or a user's Classes, keys only:
/// `Installer\Dependencies\<P>` with `P` listed, and `Installer\Dependencies\<P>\Dependents\<B>` with `B`
/// listed.
///
/// `...` is `SOFTWARE\Microsoft\Windows\CurrentVersion` of `HKLM`, either view.
fn installer_shape(l: &RegLogical, target: &Target, ex: &Exemptions<'_>) -> bool {
    let products: Vec<&str> = ex
        .gone_msi_products
        .iter()
        .map(String::as_str)
        .filter(|p| is_packed_code(p))
        .collect();
    let product = |name: &str| products.iter().any(|p| p.eq_ignore_ascii_case(name));
    let burn = |segment: &str| {
        ex.gone_burn
            .iter()
            .any(|b| !b.is_empty() && !b.contains(['\\', '*']) && fold(b) == segment)
    };
    let full = &l.full;
    let msi = l.machine && full.len() > MSI_ROOT.len() && full[..MSI_ROOT.len()] == MSI_ROOT;
    let user = matches!(l.key.hive, purge_model::Hive::Hku(_));
    let machine_classes = l.classes.as_deref().filter(|_| l.machine);
    match target {
        Target::RegKey { .. } => {
            let userdata_product = msi
                && full.len() == 9
                && full[5] == "userdata"
                && full[7] == "products"
                && product(&full[8]);
            let classes_product = machine_classes.is_some_and(|c| {
                c.len() == 3
                    && c[0] == "installer"
                    && (c[1] == "products" || c[1] == "features")
                    && product(&c[2])
            });
            let user_product = user
                && full.len() == 5
                && full[..4] == ["software", "microsoft", "installer", "products"]
                && product(&full[4]);
            let burn_key = l.classes.as_deref().is_some_and(|c| {
                c.len() >= 3
                    && c[0] == "installer"
                    && c[1] == "dependencies"
                    && ((c.len() == 3 && burn(&c[2]))
                        || (c.len() == 5 && c[3] == "dependents" && burn(&c[4])))
            });
            userdata_product || classes_product || user_product || burn_key
        }
        Target::RegValue { name, .. } => {
            let upgrade = msi && full.len() == 7 && full[5] == "upgradecodes";
            let classes_upgrade = machine_classes
                .is_some_and(|c| c.len() == 3 && c[0] == "installer" && c[1] == "upgradecodes");
            let component =
                msi && full.len() == 9 && full[5] == "userdata" && full[7] == "components";
            let folders = msi && full.len() == 6 && full[5] == "folders";
            ((upgrade || classes_upgrade || component) && product(name))
                || (folders && !name.is_empty() && !products.is_empty())
        }
        _ => false,
    }
}

/// A packed product code as Windows Installer stores it: 32 hex digits.
fn is_packed_code(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Per-user environment variables that Windows defines; deleting one whole is never a cleanup.
const CORE_ENVIRONMENT_VALUES: [&str; 4] = ["Path", "PATHEXT", "TEMP", "TMP"];

/// A folded file name of the shape `<EXE>-<8 hex digits>.pf`: a single prefetch trace (§5.10). The other
/// files of the Prefetch folder (`Layout.ini`, the `Ag*.db` databases, `PfPre_*.mkd`) and anything else
/// that merely ends in `.pf` stay under the `%WINDIR%` rule.
fn is_prefetch_trace(name: &str) -> bool {
    name.strip_suffix(".pf")
        .and_then(|stem| stem.rsplit_once('-'))
        .is_some_and(|(exe, hash)| {
            !exe.is_empty() && hash.len() == 8 && hash.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// The name to report among the rules that deny a target: the first that names the target itself or
/// something above it, and only failing that the first that protects something below it.
fn first_hit<'a>(hits: impl Iterator<Item = (&'a Rule, Rel)>) -> Option<String> {
    let mut below = None;
    for (rule, rel) in hits {
        if matches!(rel, Rel::Ancestor { .. }) {
            below.get_or_insert(rule);
        } else {
            return Some(rule.id.clone());
        }
    }
    below.map(|rule| rule.id.clone())
}

/// Checks one target against the deny-list for `env`.
///
/// Compiles the list on every call; use [`DenyList`] to check many targets.
pub fn check(target: &Target, env: &GuardEnv, exemptions: &Exemptions<'_>) -> Option<Blocker> {
    DenyList::compile(env).check(target, exemptions)
}
