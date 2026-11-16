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

pub use shared::{SharedComponent, SharedComponents, shared_components};

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Exemptions {
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
}

/// A carve-out a rule honours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exempt {
    Skeleton,
    StartMenu,
    Prefetch,
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
        let build = |env: &GuardEnv| -> Result<(Vec<Rule>, Vec<RootOnly>), String> {
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
            Ok((all, rules::root_only(env)?))
        };
        match build(&norm) {
            Ok((rules, root_only)) => DenyList {
                env: env.clone(),
                norm,
                rules,
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
    pub fn check(&self, target: &Target, exemptions: &Exemptions) -> Option<Blocker> {
        self.denying_rule(target, exemptions)
            .map(|rule| Blocker::DenyListed { rule })
    }

    /// The name of the rule that denies the target, if any.
    pub fn denying_rule(&self, target: &Target, exemptions: &Exemptions) -> Option<String> {
        let location = matches!(target, Target::Path { .. }) || target.is_registry();
        if !location {
            return None;
        }
        if self.invalid.is_some() {
            return Some("guard.unavailable".to_owned());
        }
        match target {
            Target::Path { path } => self.check_path(path, exemptions),
            other => self.check_key(other, key_of(other)?, exemptions),
        }
    }

    fn check_path(&self, path: &str, ex: &Exemptions) -> Option<String> {
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
        first_hit(self.rules.iter().filter_map(|rule| {
            let lifted = match rule.exempt {
                Some(Exempt::Prefetch) => prefetch_file,
                Some(Exempt::StartMenu) => start_menu_entry,
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

    /// The folded segments of the canonical form of `path`, or the `canon.*` rule that refuses it.
    fn path_segments(&self, path: &str, long_names_resolved: bool) -> Result<Vec<String>, String> {
        let canon =
            canon_path(path, &self.norm, None).map_err(|e| format!("canon.{}", e.code()))?;
        if canon.needs_long_name && !long_names_resolved {
            return Err("canon.short-name-unresolved".to_owned());
        }
        Ok(split_fold(&canon.path))
    }

    fn check_key(&self, target: &Target, key_path: &str, ex: &Exemptions) -> Option<String> {
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
            let lifted = rule.exempt == Some(Exempt::Skeleton)
                && ex.proven_owned_skeleton
                && is_key
                && rel == Rel::Exact;
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
        let target = Target::Path {
            path: path.to_owned(),
        };
        if let Some(rule) = self.denying_rule(&target, &ex) {
            return Some(rule);
        }
        let segs = self.path_segments(path, long_names_resolved).ok()?;
        self.root_only
            .iter()
            .find(|(_, pattern)| matches!(relate(pattern, &segs), Some(Rel::Exact | Rel::Inside)))
            .map(|(id, _)| (*id).to_owned())
    }
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
pub fn check(target: &Target, env: &GuardEnv, exemptions: &Exemptions) -> Option<Blocker> {
    DenyList::compile(env).check(target, exemptions)
}
