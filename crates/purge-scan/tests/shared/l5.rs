//! Invariant L5 of BASELINE_LOCAL_DESIGN.md (§2, §4.6) over a scanner test world, shared by the test
//! crates of this directory (`#[path = "../shared/l5.rs"] mod l5;`).
//!
//! The local baseline is presence-only, so a view below Exact may only take away: **what a scan
//! offers with a view below Exact, the scan without a baseline offers at least as strongly.** For
//! every candidate of the scan below Exact there is a candidate of the no-baseline scan that
//!
//! 1. is the same candidate (the same id), or, when there is none, has a target that contains it (a
//!    key for a key or value in it, a directory for a path in it): nothing new is offered, not even as
//!    Blocked. The containing case is the one named exception to "the same target": a scanner that
//!    is told a key is Windows' own may stop offering the key and offer the app's values in it;
//! 2. has a band at least as high, where Blocked < Weak < Likely < Safe ([`band_rank`]) and a target
//!    that is not listed is below all of them: no band is raised;
//! 3. is preselected if the candidate below Exact is.
//!
//! A candidate the no-baseline scan lists and the scan below Exact does not is fine: a scanner may
//! withhold what Windows owns. `xtask replay` checks the same property over two whole plans
//! (`l5_violations`).
//!
//! What [`check`] runs:
//!
//! 1. a view below Exact that holds **nothing the scan meets** gives exactly the candidates of the
//!    no-baseline scan, whatever its trust and however permissive its rules (an A site never sees
//!    inferred absence);
//! 2. views below Exact that say "Windows has it" of what the no-baseline scan touches (every key,
//!    value, directory, file, service, task and firewall rule its candidates name, then seeded random
//!    parts of that list: the parent and not the child, one value and not its key) hold the property
//!    above, and what was Blocked is still Blocked or no longer listed.
//!
//! Bands come from the real policy (`purge_policy::band::decide`), asked with the trust a presence-only
//! scan hands on (None) and with the view's own trust (the backstop P-BL-1 on).
//!
//! Not vacuous: [`Checked::must_offer`] and [`Tally`] fail a test whose scanner offers nothing without
//! a baseline, and one whose candidates no presence view changes, unless the test names the scanner
//! as exempt and says why.

// Each test crate of this directory uses its own part of this file.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use purge_guard::prefix;
use purge_index::baseline_view::{BaselineView, fixture};
use purge_model::{Band, BaselineTrust, Candidate, CandidateId, OsInfo, Target};
use purge_policy::band::{PolicyCtx, TargetScope, decide};

/// The tasks' tree in the registry, followed by the task path (as SYS-TASK and the harvest use it).
const TASK_TREE: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

/// Random partial-presence views per [`check`].
const DRAWS: usize = 16;

/// How strongly a scan offers a candidate: Blocked 1, Weak 2, Likely 3, Safe 4. A target the scan does
/// not list has 0.
pub fn band_rank(band: Band) -> u8 {
    match band {
        Band::Blocked => 1,
        Band::Weak => 2,
        Band::Likely => 3,
        Band::Safe => 4,
    }
}

/// The registry key a registry target is or lies in.
fn reg_key(target: &Target) -> Option<&str> {
    match target {
        Target::RegKey { path }
        | Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => Some(path),
        _ => None,
    }
}

/// Whether removing `outer` removes `inner` too and they are not the same target: a registry key with a
/// key below it or with a value (or a segment of a value) of a key at or below it, or a directory with
/// a path below it.
fn contains(outer: &Target, inner: &Target) -> bool {
    match (outer, inner) {
        (Target::RegKey { path: outer }, Target::RegKey { path: inner }) => {
            prefix::is_inside(inner, outer)
        }
        (Target::RegKey { path: outer }, inner) => {
            reg_key(inner).is_some_and(|key| prefix::is_same_or_inside(key, outer))
        }
        (Target::Path { path: outer }, Target::Path { path: inner }) => {
            prefix::is_inside(inner, outer)
        }
        _ => false,
    }
}

/// What the candidates name, as entries of a fixture view (`fixture::shipped`): the registry keys (a
/// key target, the key of a value target, and every ancestor of both down to depth 3, so that a
/// presence view also holds the containers above them), the values, the files and directories (a path
/// target, entered as a directory and as a file), the keys of the services and tasks, and the values
/// of the firewall rules.
fn entries_of(candidates: &[Candidate]) -> Vec<String> {
    let mut entries = BTreeSet::new();
    for c in candidates {
        let key = match &c.target {
            Target::RegKey { path } => path.clone(),
            Target::RegValue { path, name }
            | Target::RegValueChanged { path, name, .. }
            | Target::RegMultiSzSegment { path, name, .. } => {
                entries.insert(fixture::value_entry(path, name));
                path.clone()
            }
            Target::Path { path } => {
                entries.insert(path.clone());
                entries.insert(fixture::file_entry(path));
                continue;
            }
            // Where a baseline records that Windows has the object (the object guard's `in_baseline`).
            Target::Service { name } => {
                entries.insert(format!(r"{}\{name}", purge_index::sysobj::SERVICES_KEY));
                continue;
            }
            Target::Task { path } => {
                entries.insert(format!("{TASK_TREE}{path}"));
                continue;
            }
            Target::FirewallRule { id } => {
                entries.insert(fixture::value_entry(
                    purge_index::sysobj::FIREWALL_RULES_KEY,
                    id,
                ));
                continue;
            }
            Target::AppxPackage { .. } => continue,
        };
        let segments: Vec<&str> = key.split('\\').collect();
        for depth in 3..=segments.len() {
            entries.insert(segments[..depth].join("\\"));
        }
    }
    entries.into_iter().collect()
}

/// A candidate with the policy's verdict on it.
struct Banded<'a> {
    c: &'a Candidate,
    band: Band,
    preselected: bool,
}

fn bands(candidates: &[Candidate], trust: BaselineTrust) -> Vec<Banded<'_>> {
    candidates
        .iter()
        .map(|c| {
            let per_user = reg_key(&c.target).is_some_and(|path| {
                path.get(..4)
                    .is_some_and(|root| root.eq_ignore_ascii_case(r"HKU\"))
            });
            let d = decide(
                c,
                &PolicyCtx {
                    baseline_trust: trust,
                    mode: purge_model::ScanMode::Post,
                    verify_gone: purge_model::VerifyGone::new(true, true, true),
                    target_scope: if per_user {
                        TargetScope::PerUser
                    } else {
                        TargetScope::Machine
                    },
                },
            );
            Banded {
                c,
                band: d.band,
                preselected: d.preselected,
            }
        })
        .collect()
}

/// The violations of the property of the module documentation for one pair of scans, one line each;
/// empty when it holds. `none` is banded at trust None, `below` at `trust`.
fn violations(none: &[Candidate], below: &[Candidate], trust: BaselineTrust) -> Vec<String> {
    let mut out = Vec::new();
    let none_bands = bands(none, BaselineTrust::None);
    let below_bands = bands(below, trust);
    for b in &below_bands {
        let rank = band_rank(b.band);
        let same: Vec<&Banded<'_>> = none_bands.iter().filter(|n| n.c.id == b.c.id).collect();
        // The same candidate decides when the no-baseline scan has it; a container only stands in
        // for a candidate that scan does not have.
        let cover: Vec<&Banded<'_>> = if same.is_empty() {
            none_bands
                .iter()
                .filter(|n| contains(&n.c.target, &b.c.target))
                .collect()
        } else {
            same
        };
        if cover.is_empty() {
            out.push(format!(
                "new: {:?} is offered ({:?}) below Exact and not without a baseline, neither itself \
                 nor a key or directory that contains it: {:#?}",
                b.c.target, b.band, b.c
            ));
        } else if !cover.iter().any(|n| band_rank(n.band) >= rank) {
            out.push(format!(
                "raised: the band of {:?} is {:?} below Exact, without a baseline {:?}: {:#?}",
                b.c.target,
                b.band,
                cover.iter().map(|n| n.band).collect::<Vec<_>>(),
                b.c
            ));
        } else if b.preselected
            && !cover
                .iter()
                .any(|n| n.preselected && band_rank(n.band) >= rank)
        {
            out.push(format!(
                "preselected: {:?} is preselected ({:?}) below Exact and was not without a \
                 baseline: {:#?}",
                b.c.target, b.band, b.c
            ));
        }
    }
    // What was Blocked is still Blocked or no longer listed (it follows from the above for the same
    // id; stated on its own because it is the half a user is protected by).
    let below_by_id: BTreeMap<&CandidateId, Vec<Band>> =
        below_bands.iter().fold(BTreeMap::new(), |mut map, b| {
            map.entry(&b.c.id).or_default().push(b.band);
            map
        });
    for n in &none_bands {
        if n.band != Band::Blocked {
            continue;
        }
        let still = below_by_id.get(&n.c.id).cloned().unwrap_or_default();
        if !still.iter().all(|band| *band == Band::Blocked) {
            out.push(format!(
                "unblocked: {:?} was Blocked without a baseline and is {still:?} below Exact",
                n.c.target
            ));
        }
    }
    out
}

fn assert_monotone(what: &str, none: &[Candidate], below: &[Candidate], trust: BaselineTrust) {
    let found = violations(none, below, trust);
    assert!(
        found.is_empty(),
        "{what}: L5 does not hold:\n{}",
        found.join("\n")
    );
}

/// The comparison itself can fail, shown on the candidates of this very scan: against a scan that
/// offers nothing every candidate is new, and against the same candidates with a `WindowsBaseline`
/// block every candidate the policy offers is raised and every preselected one is preselected only
/// here.
fn assert_the_comparison_bites(what: &str, none: &[Candidate]) {
    if none.is_empty() {
        return;
    }
    let all_new = violations(&[], none, BaselineTrust::None);
    assert_eq!(
        all_new.iter().filter(|l| l.starts_with("new: ")).count(),
        none.len(),
        "{what}: the comparison does not see a new candidate"
    );
    let blocked: Vec<Candidate> = none
        .iter()
        .cloned()
        .map(|mut c| {
            c.blockers.push(purge_model::Blocker::WindowsBaseline);
            c
        })
        .collect();
    assert!(
        bands(&blocked, BaselineTrust::None)
            .iter()
            .all(|b| b.band == Band::Blocked && !b.preselected),
        "{what}: a WindowsBaseline block does not block"
    );
    let offered = bands(none, BaselineTrust::None)
        .iter()
        .filter(|b| b.band != Band::Blocked)
        .count();
    let raised = violations(&blocked, none, BaselineTrust::None);
    assert_eq!(
        raised.iter().filter(|l| l.starts_with("raised: ")).count(),
        offered,
        "{what}: the comparison does not see a raised band"
    );
    // And a scan compared with itself holds.
    assert!(violations(none, none, BaselineTrust::None).is_empty());
}
/// A view below Exact holding `entries`, the `kind`-th of the four presence shapes.
fn presence_view(kind: usize, os: &OsInfo, entries: &[&str]) -> (&'static str, BaselineView) {
    let (e, b, u) = (os.edition.as_str(), os.build, os.ubr);
    match kind % 4 {
        0 => (
            "merged, local has",
            fixture::merged_view(e, b, u, entries, &[]),
        ),
        1 => (
            "merged, neighbour has",
            fixture::merged_view(e, b, u, &[], entries),
        ),
        2 => ("local", fixture::local_view(e, b, u, entries)),
        _ => (
            "none with a neighbour",
            fixture::none_view(e, b, u, entries),
        ),
    }
}

/// A small deterministic generator (xorshift64*), seeded from the name of the check.
struct Rng(u64);

impl Rng {
    fn seeded(text: &str) -> Rng {
        // FNV-1a.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in text.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        Rng(h | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// What [`check`] saw.
#[derive(Debug)]
pub struct Checked {
    /// The candidates of the scan without a baseline.
    pub none: Vec<Candidate>,
    /// How many presence views were tried in the second half.
    pub views: usize,
    /// How many of them changed the candidates (took one away, blocked one, changed its evidence).
    pub changed: usize,
}

impl std::ops::Deref for Checked {
    type Target = Vec<Candidate>;

    fn deref(&self) -> &Vec<Candidate> {
        &self.none
    }
}

impl Checked {
    /// Fails unless the no-baseline scan offers a candidate of each of `scanners`: a check over a
    /// scanner that offers nothing shows nothing.
    pub fn must_offer(&self, what: &str, scanners: &[&str]) -> &Self {
        for id in scanners {
            assert!(
                self.none.iter().any(|c| c.scanner == *id),
                "{what}: {id} offers nothing without a baseline, so L5 is not shown for it: {:?}",
                self.none
                    .iter()
                    .map(|c| (&c.scanner, &c.target))
                    .collect::<Vec<_>>()
            );
        }
        self
    }

    /// Fails unless some presence view changed the candidates: a presence site that stopped working
    /// below Exact would otherwise pass unseen.
    pub fn must_change(&self, what: &str) -> &Self {
        assert!(
            self.changed > 0,
            "{what}: none of {} presence views changed the {} candidate(s) of the no-baseline scan",
            self.views,
            self.none.len()
        );
        self
    }
}

/// Per scanner over the worlds of one test: what it offers without a baseline, and whether presence
/// ever changed it.
#[derive(Debug, Default)]
pub struct Tally {
    /// Scanner id to (candidates offered without a baseline, presence views that changed them).
    seen: BTreeMap<String, (usize, usize)>,
}

impl Tally {
    /// Adds what [`check`] saw for one scanner in one world.
    pub fn add(&mut self, scanner: &str, checked: &Checked) {
        let e = self.seen.entry(scanner.to_owned()).or_default();
        e.0 += checked.none.len();
        e.1 += checked.changed;
    }

    /// Fails unless every scanner offers something in some world, and some presence view changed what
    /// it offers. `offers_nothing` and `presence_changes_nothing` name the scanners that are exempt
    /// from one of the two, each with the reason; an exemption that is no longer true fails as well.
    pub fn assert_not_vacuous(
        &self,
        offers_nothing: &[(&str, &str)],
        presence_changes_nothing: &[(&str, &str)],
    ) {
        let exempt = |list: &[(&str, &str)], id: &str| list.iter().any(|(s, _)| *s == id);
        for (id, _) in offers_nothing.iter().chain(presence_changes_nothing) {
            assert!(
                self.seen.contains_key(*id),
                "{id} is named exempt and was not checked: {:?}",
                self.seen
            );
        }
        for (id, (offered, changed)) in &self.seen {
            if exempt(offers_nothing, id) {
                assert_eq!(
                    *offered, 0,
                    "{id} is named as offering nothing in these worlds and offers {offered}"
                );
                continue;
            }
            assert!(
                *offered > 0,
                "{id} offers nothing without a baseline in any world of this test, so L5 is not \
                 shown for it: {:?}",
                self.seen
            );
            if exempt(presence_changes_nothing, id) {
                assert_eq!(
                    *changed, 0,
                    "{id} is named as untouched by presence and {changed} view(s) changed it"
                );
            } else {
                assert!(
                    *changed > 0,
                    "no presence view changed what {id} offers in any world of this test: {:?}",
                    self.seen
                );
            }
        }
    }
}

/// Checks L5 for one scan. `scan` runs the scanner over a fresh copy of the world with the given
/// baseline (`None`: no baseline at all) and returns its candidates.
pub fn check(
    what: &str,
    os: &OsInfo,
    scan: &dyn Fn(Option<BaselineView>) -> Vec<Candidate>,
) -> Checked {
    let none = scan(None);
    assert_the_comparison_bites(what, &none);

    // 1. Nothing the scan meets is in the view: the no-baseline scan, exactly.
    for which in 1..fixture::BELOW_EXACT {
        let view = fixture::below_exact(which, os).expect("a view");
        let trust = view.trust();
        let below = scan(Some(view));
        assert_eq!(
            below, none,
            "{what}: a {trust} view that holds nothing differs from no baseline"
        );
    }

    // 2. Windows has what the scan touches: only takes away.
    let entries = entries_of(&none);
    let all: Vec<&str> = entries.iter().map(String::as_str).collect();
    let mut views: Vec<(String, BaselineView)> = (0..4)
        .map(|kind| {
            let (name, view) = presence_view(kind, os, &all);
            (name.to_owned(), view)
        })
        .collect();
    // Parts of the list: each entry in or out with a probability that differs per draw, so that
    // small and large parts both occur.
    let mut rng = Rng::seeded(what);
    if all.len() > 1 {
        for draw in 0..DRAWS {
            let keep = 1 + rng.next() % 7;
            let part: Vec<&str> = all
                .iter()
                .copied()
                .filter(|_| rng.next() % 8 < keep)
                .collect();
            let (name, view) = presence_view(draw, os, &part);
            views.push((
                format!(
                    "{name}, draw {draw}: {} of {} entries",
                    part.len(),
                    all.len()
                ),
                view,
            ));
        }
    }
    let mut changed = 0;
    let tried = views.len();
    for (name, view) in views {
        let trust = view.trust();
        let below = scan(Some(view));
        let what = format!("{what} ({name})");
        // What a presence-only scan hands to the policy, and the view's own trust (P-BL-1 on).
        assert_monotone(&what, &none, &below, trust.presence_only());
        assert_monotone(&what, &none, &below, trust);
        // No evidence of a key rests on absence below Exact.
        for c in &below {
            assert!(
                !c.evidence
                    .iter()
                    .any(|e| purge_scan::framework::claims_absence(e, &c.target)),
                "{what}: {:?} claims baseline absence below Exact: {c:#?}",
                c.target
            );
            assert!(
                !c.blockers.contains(&purge_model::Blocker::BaselineInferred),
                "{what}: {:?} carries BaselineInferred: no production path infers absence",
                c.target
            );
        }
        changed += usize::from(below != none);
    }
    // `PURGE_L5_PRINT=1 cargo test -p purge-scan l5_ -- --nocapture` lists what each check saw.
    if std::env::var_os("PURGE_L5_PRINT").is_some() {
        let mut by_scanner: BTreeMap<&str, usize> = BTreeMap::new();
        for c in &none {
            *by_scanner.entry(c.scanner.as_str()).or_default() += 1;
        }
        eprintln!(
            "L5 {what}: without a baseline {by_scanner:?}; {changed} of {tried} presence views \
             changed it"
        );
    }
    Checked {
        none,
        views: tried,
        changed,
    }
}
