//! The baseline view: what the engine asks instead of one exact baseline
//! (BASELINE_LOCAL_DESIGN.md §4; invariants L1 to L7 of §2).
//!
//! A view answers two different questions with different trust:
//!
//! - **Presence (P)**: "is this Windows' own?" Any set the view holds may say yes: the exact shipped
//!   baseline, or the local baseline together with the shipped neighbours. The answer is the union and
//!   only ever adds (L1); a wrong "present" costs a missed leftover.
//! - **Absence (A)**: "is this key proven not Windows' own?" Only [`BaselineView::key_absent`] answers
//!   it, as an [`Absence`] that carries the trust. A wrong "absent" can offer a Windows key, so
//!   everything doubtful is [`Absence::Unknown`].
//!
//! # Trust ([`BaselineTrust`])
//!
//! | Trust | When | Presence from | Absence |
//! |---|---|---|---|
//! | Exact | a shipped baseline of exactly the host's (edition, build, ubr) | that baseline only | [`Absence::Proven`] inside the capture scope |
//! | Merged | no exact one; a complete local baseline of the host; at least one neighbour | local ∪ neighbours | [`Absence::Inferred`] in the areas marked `merged` |
//! | Local | as Merged, without a neighbour | local | [`Absence::Inferred`] in the areas marked `local` (none today) |
//! | None | anything else | whatever exists (L2: an incomplete local baseline is presence-only) | never |
//!
//! The exact baseline is never mixed with anything: an Exact view holds that one [`Baseline`] and every
//! method returns what the baseline returns (L3). Below Exact the view never answers
//! [`Absence::Proven`] and never hands out a value's data ([`BaselineView::exact_value`]).
//!
//! # When absence is inferred
//!
//! `key_absent` answers [`Absence::Inferred`] only when **all** of these hold; otherwise it is
//! `Present` or `Unknown`:
//!
//! 1. no set has the key, by the rules of [`Baseline::has_key`] (twin of a 32-bit spelling included);
//! 2. the trust is Merged or Local;
//! 3. the key is spelled with a bound root (`HKLM`, `HKU`, `HKCU`); `HKCR` names two hives and gets
//!    `Unknown`;
//! 4. the key is inside the capture scope ([`Baseline::key_in_scope`]);
//! 5. the key is not at or below a key the local baseline's builder could not read (its `#src` lines
//!    name them; review BL-RM M4);
//! 6. the key's area in `view.json` ([`ViewRules::area_of`]) is marked for that trust. A key outside
//!    every area is never marked.
//!
//! # No difference, no negative cache
//!
//! The union is "any set has the hash". Nothing is subtracted from a set and no "known absent" answer
//! is kept (§6): a hash collision can only make a key look present, the safe side.
//!
//! # Input for a derived cache form
//!
//! Parsing the text files is the cost of a load (the local file alone is over the view's budget). The
//! view's parts can be rebuilt from their hashed sets without the text:
//! [`LocalBaseline::from_hashed_sets`] and [`Neighbour::from_hashed_sets`] over [`HashedSets`], with
//! [`HashedSets::scheme`] naming the normalisation they were made with. The exact baseline has no such
//! door: it is always parsed from its shipped file.
//!
//! [`HashedSets`]: crate::baseline::HashedSets
//! [`HashedSets::scheme`]: crate::baseline::HashedSets::scheme

#[doc(hidden)]
pub mod fixture;
mod neighbours;
mod rules;
#[cfg(test)]
mod tests;

use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

pub use neighbours::{
    HostOs, Neighbour, NeighbourFile, load_neighbours, rank_neighbours, select_neighbours,
};
pub use rules::{
    Area, AreaShape, MAX_NEIGHBOUR_COUNT, MAX_VIEW_FILE_BYTES, NeighbourRule, VIEW_FILE_NAME,
    VIEW_SCHEMA, ViewRules, ViewRulesError,
};

use crate::baseline::{Baseline, BaselineValue, PathKind, key_forms, normalised_key, under};
use crate::local_baseline::{LocalBaseline, SourceLine};

/// How much an absence answer of a view is worth: the engine's one trust type, shared with the policy
/// and the fingerprint. See the module documentation.
pub use purge_model::BaselineTrust;

/// What a view knows about a key not being Windows' own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum Absence {
    /// Some set of the view has the key: it is Windows' own.
    Present,
    /// Exact trust, inside the capture scope, not in the baseline: proof, as before the view.
    Proven,
    /// Merged or Local trust, inside the capture scope, in an area marked for that trust, in no set.
    /// Never proof: the caller must carry the cap (L4, `Blocker::BaselineInferred`).
    Inferred(BaselineTrust),
    /// Nothing can be said: trust None, outside the scope, outside the marked areas, below a key the
    /// builder could not read, or an unbound spelling.
    Unknown,
}

impl Absence {
    /// Whether some set has the key.
    pub fn is_present(self) -> bool {
        self == Absence::Present
    }
}

#[derive(Clone)]
enum Inner {
    Exact(Box<Baseline>),
    Union(Box<Union>),
}

#[derive(Clone)]
struct Union {
    trust: BaselineTrust,
    local: Option<LocalBaseline>,
    neighbours: Vec<Neighbour>,
    rules: ViewRules,
    /// Normalised keys the local baseline's builder could not read; absence is unknown at and below
    /// them. Empty unless the trust is Merged or Local.
    unreadable: Vec<String>,
}

impl Union {
    fn any(&self, has: impl Fn(&Baseline) -> bool) -> bool {
        self.local.as_ref().is_some_and(|l| has(l.sets()))
            || self.neighbours.iter().any(|n| has(n.sets()))
    }
}

/// The view of "Windows' own" a scan or harvest works with. See the module documentation.
#[derive(Clone)]
pub struct BaselineView {
    inner: Inner,
    warnings: Vec<String>,
}

impl fmt::Debug for BaselineView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaselineView")
            .field("name", &self.name())
            .field("trust", &self.trust())
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl BaselineView {
    /// The view over the shipped baseline of exactly the host's Windows. The caller has selected it
    /// with [`Baseline::select`] / [`Baseline::try_select`] (name and header match); nothing else is
    /// consulted (L3).
    pub fn exact(baseline: Baseline) -> BaselineView {
        BaselineView {
            inner: Inner::Exact(Box::new(baseline)),
            warnings: Vec::new(),
        }
    }

    /// The view below Exact that the parts support, for `host`:
    ///
    /// - trust **Merged** when `local` is a complete local baseline of exactly `host` whose `#src`
    ///   lines name every unreadable key, and at least one neighbour qualifies;
    /// - trust **Local** when that holds without a neighbour;
    /// - trust **None** otherwise; the local baseline, if any, still answers presence (L2).
    ///
    /// The neighbours are put through the selection rule again ([`rank_neighbours`]): the exact
    /// baseline of `host`, one beyond the distance limit and those beyond `max_count` are dropped.
    /// Everything that lowered the trust or was dropped is in [`BaselineView::warnings`].
    pub fn assemble(
        host: &HostOs,
        local: Option<LocalBaseline>,
        neighbours: Vec<Neighbour>,
        rules: &ViewRules,
    ) -> BaselineView {
        Self::union(host, local, neighbours, rules, false)
    }

    /// [`BaselineView::assemble`] with a local baseline and neighbours: trust Merged when the parts
    /// support it, less when they do not.
    pub fn merged(
        host: &HostOs,
        local: LocalBaseline,
        neighbours: Vec<Neighbour>,
        rules: &ViewRules,
    ) -> BaselineView {
        Self::union(host, Some(local), neighbours, rules, false)
    }

    /// [`BaselineView::assemble`] with a local baseline and no neighbour: trust Local when the local
    /// baseline supports it, None when it does not.
    pub fn local(host: &HostOs, local: LocalBaseline, rules: &ViewRules) -> BaselineView {
        Self::union(host, Some(local), Vec::new(), rules, false)
    }

    /// A view of trust None over whatever exists: presence from the neighbours and from a local
    /// baseline in any state, absence never.
    pub fn none(
        host: &HostOs,
        local: Option<LocalBaseline>,
        neighbours: Vec<Neighbour>,
        rules: &ViewRules,
    ) -> BaselineView {
        Self::union(host, local, neighbours, rules, true)
    }

    /// The view for `host` from the shipped baseline directory `dir`.
    ///
    /// With a shipped baseline of exactly `host` the view is Exact and `local` is **not called** (L3:
    /// the local baseline is not built or read). Otherwise `view.json` is read ([`ViewRules`]; a
    /// missing or refused file marks no area), the neighbours are selected and loaded, `local` is
    /// called on another thread meanwhile, and the parts go through [`BaselineView::assemble`].
    ///
    /// `local` returns the host's local baseline if there is a usable one (the cache's business:
    /// directory check, source id, a derived form). A shipped file with the exact name that is
    /// unusable is reported in the warnings and is not a neighbour either.
    pub fn open<F>(dir: &Path, host: &HostOs, local: F) -> BaselineView
    where
        F: FnOnce() -> Option<LocalBaseline> + Send,
    {
        let mut warnings = Vec::new();
        if host.edition.is_empty() {
            warnings
                .push("baseline: the Windows edition is unknown; no exact baseline is used".into());
        } else {
            match Baseline::try_select(dir, &host.edition, host.build, host.ubr) {
                Ok(Some(exact)) => return Self::exact(exact),
                Ok(None) => {}
                Err(e) => warnings.push(format!(
                    "baseline: {} in {} is unusable ({e})",
                    Baseline::file_name(&host.edition, host.build, host.ubr),
                    dir.display()
                )),
            }
        }
        let rules = ViewRules::load_or_closed(dir, &mut warnings);
        let (local, neighbours) = std::thread::scope(|scope| {
            let local = scope.spawn(local);
            let neighbours = load_neighbours(dir, host, rules.neighbours(), &mut warnings);
            let local = local
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            (local, neighbours)
        });
        let mut view = Self::assemble(host, local, neighbours, &rules);
        warnings.append(&mut view.warnings);
        view.warnings = warnings;
        view
    }

    fn union(
        host: &HostOs,
        local: Option<LocalBaseline>,
        neighbours: Vec<Neighbour>,
        rules: &ViewRules,
        presence_only: bool,
    ) -> BaselineView {
        let mut warnings = Vec::new();

        // The neighbours, by the rule; what the rule does not choose is not used.
        let rule = rules.neighbours();
        let order = rank_neighbours(
            host,
            neighbours.iter().map(|n| (n.edition(), n.build(), n.ubr())),
            rule,
        );
        let mut slots: Vec<Option<Neighbour>> = neighbours.into_iter().map(Some).collect();
        let kept: Vec<Neighbour> = order
            .into_iter()
            .take(rule.max_count)
            .filter_map(|i| slots[i].take())
            .collect();
        for dropped in slots.into_iter().flatten() {
            warnings.push(format!(
                "baseline: {} is not used as a neighbour of {} (the exact baseline, more than {} \
                 builds away, or beyond the {} nearest)",
                dropped.name(),
                host.name(),
                rule.max_build_distance,
                rule.max_count
            ));
        }

        // Whether the local baseline supports absence, and the keys below which it does not.
        let mut unreadable = Vec::new();
        let supports_absence = match &local {
            None => {
                warnings.push(format!(
                    "baseline: no local baseline of {}; absence is never inferred",
                    host.name()
                ));
                false
            }
            Some(l) => {
                let h = l.header();
                if !host.is(&h.edition, h.build, h.ubr) {
                    warnings.push(format!(
                        "baseline: the local baseline is of {}-{}.{}, this Windows is {}; it is \
                         used for presence only",
                        h.edition,
                        h.build,
                        h.ubr,
                        host.name()
                    ));
                    false
                } else if !l.complete() {
                    warnings.push(format!(
                        "baseline: the local baseline is incomplete ({}); it is used for presence \
                         only",
                        l.incomplete_reasons().join("; ")
                    ));
                    false
                } else {
                    match unreadable_keys(l.sources()) {
                        Ok(keys) => {
                            unreadable = keys;
                            true
                        }
                        Err(why) => {
                            warnings.push(format!(
                                "baseline: the local baseline does not name its unreadable keys \
                                 ({why}); it is used for presence only"
                            ));
                            false
                        }
                    }
                }
            }
        };
        let trust = if presence_only || !supports_absence {
            BaselineTrust::None
        } else if kept.is_empty() {
            BaselineTrust::Local
        } else {
            BaselineTrust::Merged
        };
        if trust == BaselineTrust::None {
            unreadable.clear();
        }
        BaselineView {
            inner: Inner::Union(Box::new(Union {
                trust,
                local,
                neighbours: kept,
                rules: rules.clone(),
                unreadable,
            })),
            warnings,
        }
    }

    /// The view that holds nothing: trust None, no set, no warning, the name `none`. It is what a
    /// caller without any baseline passes; every presence question answers no and
    /// [`BaselineView::key_absent`] answers [`Absence::Unknown`].
    pub fn empty() -> &'static BaselineView {
        static EMPTY: OnceLock<BaselineView> = OnceLock::new();
        EMPTY.get_or_init(|| BaselineView {
            inner: Inner::Union(Box::new(Union {
                trust: BaselineTrust::None,
                local: None,
                neighbours: Vec::new(),
                rules: ViewRules::closed(),
                unreadable: Vec::new(),
            })),
            warnings: Vec::new(),
        })
    }

    /// `view`, or [`BaselineView::empty`] without one.
    pub fn or_empty(view: Option<&BaselineView>) -> &BaselineView {
        view.unwrap_or_else(|| Self::empty())
    }

    /// Whether this is an Exact view whose baseline describes exactly this Windows
    /// ([`Baseline::is_for`]: the edition compares case-insensitively). The view trusts its caller's
    /// selection; a consumer that knows the Windows of a fingerprint asks here before it takes
    /// absence as proof.
    pub fn is_exact_for(&self, edition: &str, build: u32, ubr: u32) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.is_for(edition, build, ubr),
            Inner::Union(_) => false,
        }
    }

    /// Whether the view holds no set at all (no exact baseline, no local baseline, no neighbour):
    /// it can then say nothing, not even "this is Windows' own".
    pub fn holds_nothing(&self) -> bool {
        match &self.inner {
            Inner::Exact(_) => false,
            Inner::Union(u) => u.local.is_none() && u.neighbours.is_empty(),
        }
    }

    /// The trust of this view's absence answers.
    pub fn trust(&self) -> BaselineTrust {
        match &self.inner {
            Inner::Exact(_) => BaselineTrust::Exact,
            Inner::Union(u) => u.trust,
        }
    }

    /// A short name for facts and messages: `Professional-26340.9882` for an exact baseline (as its
    /// header spells it), `local-Professional-26300.9974+2` for a local baseline with two
    /// neighbours, `none+1` for one neighbour alone, `none` for an empty view.
    pub fn name(&self) -> String {
        match &self.inner {
            Inner::Exact(b) => format!("{}-{}.{}", b.edition(), b.build(), b.ubr()),
            Inner::Union(u) => {
                let mut name = match &u.local {
                    Some(l) => {
                        let h = l.header();
                        format!("local-{}-{}.{}", h.edition, h.build, h.ubr)
                    }
                    None => "none".to_owned(),
                };
                if !u.neighbours.is_empty() {
                    name.push_str(&format!("+{}", u.neighbours.len()));
                }
                name
            }
        }
    }

    /// The source id of the local baseline the view holds, if any (the fingerprint's `local_id`,
    /// §4.5).
    pub fn local_id(&self) -> Option<&str> {
        match &self.inner {
            Inner::Exact(_) => None,
            Inner::Union(u) => u.local.as_ref().map(LocalBaseline::id),
        }
    }

    /// The names of the neighbours the view holds (`<edition>-<build>.<ubr>`), best first; empty for
    /// an Exact view.
    pub fn neighbour_names(&self) -> Vec<String> {
        match &self.inner {
            Inner::Exact(_) => Vec::new(),
            Inner::Union(u) => u.neighbours.iter().map(Neighbour::name).collect(),
        }
    }

    /// What lowered the trust or was left out while the view was put together, one line each, in
    /// the engine's `baseline: …` warning form. Empty for an Exact view.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The id of the `view.json` area a key belongs to, if any (the residue output's `area`, §7).
    /// `None` for an Exact view, which has no areas.
    pub fn area_of(&self, key: &str) -> Option<&str> {
        match &self.inner {
            Inner::Exact(_) => None,
            Inner::Union(u) => u.rules.area_of(&normalised_key(key)).map(Area::id),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // P: presence. Any trust; the union of every set the view holds.
    // ---------------------------------------------------------------------------------------------

    /// Whether some set says Windows has this registry key ([`Baseline::has_key`] per set).
    pub fn has_key(&self, key: &str) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.has_key(key),
            Inner::Union(u) => u.any(|s| s.has_key(key)),
        }
    }

    /// [`Baseline::has_key_exact_view`] per set: present when any set has that very spelling or, for
    /// the shared subtrees, the twin.
    pub fn has_key_exact_view(&self, key: &str) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.has_key_exact_view(key),
            Inner::Union(u) => u.any(|s| s.has_key_exact_view(key)),
        }
    }

    /// Whether some set has a value of this name in this key (`""` is the default value).
    pub fn has_value(&self, key: &str, name: &str) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.has_value(key, name),
            Inner::Union(u) => u.any(|s| s.has_value(key, name)),
        }
    }

    /// Whether some set has this file or directory.
    pub fn has_path(&self, path: &str) -> bool {
        self.path_kind(path).is_some()
    }

    /// Whether some set has this path, and as what (the first set that has it says).
    pub fn path_kind(&self, path: &str) -> Option<PathKind> {
        match &self.inner {
            Inner::Exact(b) => b.path_kind(path),
            Inner::Union(u) => u
                .local
                .as_ref()
                .and_then(|l| l.sets().path_kind(path))
                .or_else(|| u.neighbours.iter().find_map(|n| n.sets().path_kind(path))),
        }
    }

    /// [`Baseline::has_profile_path`] per set.
    pub fn has_profile_path(&self, profile_dir: &str, path: &str) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.has_profile_path(profile_dir, path),
            Inner::Union(u) => u.any(|s| s.has_profile_path(profile_dir, path)),
        }
    }

    /// [`Baseline::has_segment`] per set.
    pub fn has_segment(&self, name: &str) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.has_segment(name),
            Inner::Union(u) => u.any(|s| s.has_segment(name)),
        }
    }

    /// [`Baseline::has_token`] per set.
    pub fn has_token(&self, token: &str) -> bool {
        match &self.inner {
            Inner::Exact(b) => b.has_token(token),
            Inner::Union(u) => u.any(|s| s.has_token(token)),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // A: absence. The only way to learn it.
    // ---------------------------------------------------------------------------------------------

    /// What the view knows about `key` not being Windows' own. See the module documentation for the
    /// conditions; anything doubtful is [`Absence::Unknown`].
    pub fn key_absent(&self, key: &str) -> Absence {
        let u = match &self.inner {
            Inner::Exact(b) => {
                return if b.has_key(key) {
                    Absence::Present
                } else if Baseline::key_in_scope(key) {
                    Absence::Proven
                } else {
                    Absence::Unknown
                };
            }
            Inner::Union(u) => u,
        };
        if u.any(|s| s.has_key(key)) {
            return Absence::Present;
        }
        if !matches!(u.trust, BaselineTrust::Merged | BaselineTrust::Local) {
            return Absence::Unknown;
        }
        // The key's own spelling decides its area. An unbound or unknown root names no one key.
        let own = normalised_key(key);
        if !matches!(own.split('\\').next(), Some("hklm" | "hku")) {
            return Absence::Unknown;
        }
        if !Baseline::key_in_scope(key) {
            return Absence::Unknown;
        }
        // What the builder could not read, the view does not know: at or below such a key (in either
        // registry view) nothing is inferred.
        if key_forms(key)
            .iter()
            .any(|form| u.unreadable.iter().any(|k| under(form, k)))
        {
            return Absence::Unknown;
        }
        match u.rules.area_of(&own) {
            Some(area) if area.accepts(u.trust) => Absence::Inferred(u.trust),
            _ => Absence::Unknown,
        }
    }

    /// The type and data hash clean Windows has for this value: the restore source of an `.ext`
    /// default. Only an Exact view has one; below Exact there is no data to restore (§3.3).
    pub fn exact_value(&self, key: &str, name: &str) -> Option<BaselineValue> {
        match &self.inner {
            Inner::Exact(b) => b.value(key, name),
            Inner::Union(_) => None,
        }
    }
}

/// The normalised keys the `#src` lines name as unreadable, or why the lines cannot be relied on to
/// name them all. A source line counts its unreadable keys (`unreadable=`) and names the first few
/// (`unreadable-keys=`, `, `-separated full paths); a complete build has only the named ones
/// (`build.rs` `hive_line`), so more counted than named, or a name that is not a registry key, means
/// the list is not the whole truth.
fn unreadable_keys(sources: &[SourceLine]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for line in sources {
        let counted: u64 = match line.fact("unreadable") {
            None => 0,
            Some(text) => text
                .parse()
                .map_err(|_| format!("{}: unreadable={text:?} is not a number", line.source))?,
        };
        let names: Vec<&str> = line
            .fact("unreadable-keys")
            .unwrap_or("")
            .split(", ")
            .filter(|name| !name.is_empty())
            .collect();
        if (names.len() as u64) < counted {
            return Err(format!(
                "{}: {counted} unreadable keys, {} named",
                line.source,
                names.len()
            ));
        }
        for name in names {
            let norm = normalised_key(name);
            let rooted = matches!(norm.split('\\').next(), Some("hklm" | "hku"));
            // The builder writes `;` in a key name as `,`: such a name is not the key's.
            if !rooted || name.contains(',') {
                return Err(format!(
                    "{}: {name:?} does not name a registry key",
                    line.source
                ));
            }
            out.push(norm);
        }
    }
    Ok(out)
}
