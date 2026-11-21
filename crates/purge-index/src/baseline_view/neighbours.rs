//! Neighbours: shipped baselines of other builds, editions or revisions that add presence to a view
//! below Exact (BASELINE_LOCAL_DESIGN.md §4.1; review BL-RM S6).
//!
//! # Selection
//!
//! Among the shipped baselines of any edition, for a host (edition, build, ubr):
//!
//! 1. the baseline of exactly the host's (edition, build, ubr) is **never** a neighbour: with it the
//!    view is Exact, and it is not mixed into a Merged answer;
//! 2. a baseline qualifies when `|Δbuild| ≤ max_build_distance`;
//! 3. the qualifying ones are ranked by `|Δbuild|` (so every baseline of the host's own build comes
//!    first), then the host's edition before any other, then the smaller `|Δubr|`, then by name;
//! 4. the first `max_count` are taken.
//!
//! This is the rule after gate M: the design's first wording took the same-build files *or else* the
//! nearest below and above, which left a retail host of a build that only has an LTSC baseline with
//! that one file although a nearer-edition baseline of another build was inside the limit. A neighbour
//! only adds presence (L1), so taking more of them is the safe direction.
//!
//! The edition does not have to match. The limits are data (`view.json`, [`NeighbourRule`]).

use std::cmp::Reverse;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use purge_model::OsInfo;

use super::rules::NeighbourRule;
use crate::baseline::{Baseline, BaselineError, HashedSets, RecordCounts, SetsError};

/// The Windows a view is for: `EditionID`, build and update build revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOs {
    /// `EditionID`, e.g. `Professional`. Compared without regard to ASCII case, as the exact loader
    /// does.
    pub edition: String,
    /// Build number.
    pub build: u32,
    /// Update build revision.
    pub ubr: u32,
}

impl HostOs {
    /// A host of this (edition, build, ubr).
    pub fn new(edition: &str, build: u32, ubr: u32) -> HostOs {
        HostOs {
            edition: edition.to_owned(),
            build,
            ubr,
        }
    }

    /// `<edition>-<build>.<ubr>`, the name a shipped baseline of this Windows has.
    pub fn name(&self) -> String {
        format!("{}-{}.{}", self.edition, self.build, self.ubr)
    }

    /// Whether this is exactly that (edition, build, ubr).
    pub fn is(&self, edition: &str, build: u32, ubr: u32) -> bool {
        self.edition.eq_ignore_ascii_case(edition) && self.build == build && self.ubr == ubr
    }
}

impl From<&OsInfo> for HostOs {
    fn from(os: &OsInfo) -> Self {
        HostOs::new(&os.edition, os.build, os.ubr)
    }
}

/// The indices of the candidates `(edition, build, ubr)` that qualify as neighbours of `host`, best
/// first; **not** cut to `rule.max_count` (a caller that has to skip an unusable file goes on down the
/// list). See the module documentation for the rule.
pub fn rank_neighbours<'a, I>(host: &HostOs, candidates: I, rule: NeighbourRule) -> Vec<usize>
where
    I: IntoIterator<Item = (&'a str, u32, u32)>,
{
    let mut ranked: Vec<_> = candidates
        .into_iter()
        .enumerate()
        .filter(|(_, (edition, build, ubr))| !host.is(edition, *build, *ubr))
        .filter_map(|(i, (edition, build, ubr))| {
            let distance = build.abs_diff(host.build);
            (distance <= rule.max_build_distance).then(|| {
                (
                    distance,
                    Reverse(edition.eq_ignore_ascii_case(&host.edition)),
                    ubr.abs_diff(host.ubr),
                    edition.to_ascii_lowercase(),
                    build,
                    ubr,
                    i,
                )
            })
        })
        .collect();
    ranked.sort();
    ranked.into_iter().map(|key| key.6).collect()
}

/// A shipped baseline file, by what its name says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighbourFile {
    /// The file.
    pub path: PathBuf,
    /// The edition in the name.
    pub edition: String,
    /// The build in the name.
    pub build: u32,
    /// The revision in the name.
    pub ubr: u32,
}

impl NeighbourFile {
    /// `<edition>-<build>.<ubr>`.
    pub fn name(&self) -> String {
        format!("{}-{}.{}", self.edition, self.build, self.ubr)
    }
}

/// `<EditionID>-<build>.<ubr>.tsv.gz` → its three parts. A local baseline's name
/// (`local-<EditionID>-<build>.<ubr>-<id>.tsv.gz`) and anything else is `None`: an edition is letters,
/// digits and `_` only, as for the exact loader.
fn parse_shipped_name(name: &str) -> Option<(String, u32, u32)> {
    const SUFFIX: &str = ".tsv.gz";
    let cut = name.len().checked_sub(SUFFIX.len())?;
    if !name.is_char_boundary(cut) || !name[cut..].eq_ignore_ascii_case(SUFFIX) {
        return None;
    }
    let (edition, version) = name[..cut].rsplit_once('-')?;
    let plain = !edition.is_empty()
        && edition
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    let (build, ubr) = version.split_once('.')?;
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    plain.then_some(())?;
    Some((edition.to_owned(), number(build)?, number(ubr)?))
}

/// Every shipped baseline file in `dir` that qualifies as a neighbour of `host`, best first, **not**
/// cut to `rule.max_count`. Only names are read.
fn ranked_files(dir: &Path, host: &HostOs, rule: NeighbourRule) -> io::Result<Vec<NeighbourFile>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some((edition, build, ubr)) = name.to_str().and_then(parse_shipped_name) else {
            continue;
        };
        if entry.file_type()?.is_dir() {
            continue;
        }
        files.push(NeighbourFile {
            path: entry.path(),
            edition,
            build,
            ubr,
        });
    }
    // The listing order of a directory is not defined; the ranking must not depend on it.
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let order = rank_neighbours(
        host,
        files.iter().map(|f| (f.edition.as_str(), f.build, f.ubr)),
        rule,
    );
    Ok(order.into_iter().map(|i| files[i].clone()).collect())
}

/// The shipped baselines in `dir` chosen as neighbours of `host`: at most `rule.max_count`, best
/// first (see the module documentation). Only file names are read here; [`Neighbour::load`] checks
/// each file's header against its name.
pub fn select_neighbours(
    dir: &Path,
    host: &HostOs,
    rule: NeighbourRule,
) -> io::Result<Vec<NeighbourFile>> {
    let mut files = ranked_files(dir, host, rule)?;
    files.truncate(rule.max_count);
    Ok(files)
}

/// A shipped baseline of another Windows, held for presence only. It is not a [`Baseline`] and gives
/// none back, so it can never be used as the exact one.
#[derive(Debug, Clone)]
pub struct Neighbour {
    sets: Baseline,
}

impl Neighbour {
    /// A parsed shipped baseline as a neighbour.
    pub fn from_baseline(baseline: Baseline) -> Neighbour {
        Neighbour { sets: baseline }
    }

    /// Loads a selected file; refused when it does not parse (a local baseline's header included,
    /// L6) or when its header names another (edition, build, ubr) than its name.
    pub fn load(file: &NeighbourFile) -> Result<Neighbour, BaselineError> {
        let baseline = Baseline::load(&file.path)?;
        if !baseline.is_for(&file.edition, file.build, file.ubr) {
            return Err(BaselineError::HeaderMismatch {
                expected: format!("{} {}.{}", file.edition, file.build, file.ubr),
                found: format!(
                    "{} {}.{}",
                    baseline.edition(),
                    baseline.build(),
                    baseline.ubr()
                ),
            });
        }
        Ok(Neighbour { sets: baseline })
    }

    /// A neighbour from the hashed sets of one that was loaded before (a derived cache form,
    /// BL-CACHE). The caller answers for the sets being those of the shipped file of this (edition,
    /// build, ubr); sets that are not strictly ascending are refused.
    pub fn from_hashed_sets(
        edition: &str,
        build: u32,
        ubr: u32,
        sets: HashedSets,
    ) -> Result<Neighbour, SetsError> {
        sets.check()?;
        Ok(Neighbour {
            sets: Baseline::from_hashed_sets(edition, build, ubr, "", "hashed sets", sets),
        })
    }

    /// The hashed membership sets ([`Neighbour::from_hashed_sets`] reads them back; store
    /// [`HashedSets::scheme`] beside them).
    pub fn into_hashed_sets(self) -> HashedSets {
        self.sets.into_hashed_sets()
    }

    /// The edition it was captured on.
    pub fn edition(&self) -> &str {
        self.sets.edition()
    }

    /// Its build.
    pub fn build(&self) -> u32 {
        self.sets.build()
    }

    /// Its revision.
    pub fn ubr(&self) -> u32 {
        self.sets.ubr()
    }

    /// `<edition>-<build>.<ubr>`.
    pub fn name(&self) -> String {
        format!("{}-{}.{}", self.edition(), self.build(), self.ubr())
    }

    /// Record lines of each type it was made from.
    pub fn counts(&self) -> RecordCounts {
        self.sets.counts()
    }

    pub(super) fn sets(&self) -> &Baseline {
        &self.sets
    }
}

impl From<Baseline> for Neighbour {
    fn from(baseline: Baseline) -> Self {
        Neighbour::from_baseline(baseline)
    }
}

/// Selects and loads the neighbours of `host` from `dir`: the best `rule.max_count` files are read in
/// parallel; a file that is unusable (unreadable, not a shipped baseline, header and name disagree) is
/// skipped with a line in `warnings`, as an unusable exact file would be, and the next one on the
/// list is tried in its place.
pub fn load_neighbours(
    dir: &Path,
    host: &HostOs,
    rule: NeighbourRule,
    warnings: &mut Vec<String>,
) -> Vec<Neighbour> {
    let files = match ranked_files(dir, host, rule) {
        Ok(files) => files,
        Err(e) => {
            warnings.push(format!(
                "baseline: cannot list {} ({e}); no neighbouring baseline is used",
                dir.display()
            ));
            return Vec::new();
        }
    };
    let (first, rest) = files.split_at(rule.max_count.min(files.len()));
    let loaded: Vec<Result<Neighbour, BaselineError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = first
            .iter()
            .map(|file| scope.spawn(move || Neighbour::load(file)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    let mut out = Vec::with_capacity(first.len());
    let skip = |file: &NeighbourFile, e: BaselineError, warnings: &mut Vec<String>| {
        warnings.push(format!(
            "baseline: the neighbouring baseline {} is unusable ({e}); it is skipped",
            file.path.display()
        ));
    };
    for (file, result) in first.iter().zip(loaded) {
        match result {
            Ok(n) => out.push(n),
            Err(e) => skip(file, e, warnings),
        }
    }
    for file in rest {
        if out.len() >= rule.max_count {
            break;
        }
        match Neighbour::load(file) {
            Ok(n) => out.push(n),
            Err(e) => skip(file, e, warnings),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: NeighbourRule = NeighbourRule {
        max_build_distance: 1000,
        max_count: 3,
    };

    /// The names chosen for `host` among `shipped`, best first, cut to the rule's count.
    fn chosen(host: &HostOs, shipped: &[(&str, u32, u32)], rule: NeighbourRule) -> Vec<String> {
        rank_neighbours(host, shipped.iter().copied(), rule)
            .into_iter()
            .take(rule.max_count)
            .map(|i| format!("{}-{}.{}", shipped[i].0, shipped[i].1, shipped[i].2))
            .collect()
    }

    #[test]
    fn the_exact_match_is_never_a_neighbour() {
        let host = HostOs::new("Professional", 26100, 1742);
        let shipped = [("Professional", 26100, 1742), ("professional", 26100, 1742)];
        assert!(chosen(&host, &shipped, RULE).is_empty());
        // The same build and revision of another edition is a neighbour, at distance 0.
        let shipped = [
            ("Professional", 26100, 1742),
            ("EnterpriseSEval", 26100, 1742),
        ];
        assert_eq!(
            chosen(&host, &shipped, RULE),
            ["EnterpriseSEval-26100.1742"]
        );
    }

    #[test]
    fn same_build_other_ubr() {
        let host = HostOs::new("Professional", 26100, 3000);
        let shipped = [
            ("EnterpriseSEval", 26100, 1742),
            ("Professional", 26100, 2000),
            ("Professional", 26100, 3500),
            ("Core", 26100, 2999),
        ];
        // All four are of the host's build; three are taken: the host's edition first, there the
        // smaller revision distance, then the other editions by revision distance.
        assert_eq!(
            chosen(&host, &shipped, RULE),
            [
                "Professional-26100.3500",
                "Professional-26100.2000",
                "Core-26100.2999"
            ]
        );
    }

    /// BL-RM S6: a same-build file does not shut out a baseline of another build inside the limit.
    #[test]
    fn same_build_first_then_the_nearest_others_fill_up() {
        let host = HostOs::new("Professional", 26100, 4000);
        let shipped = [
            ("Professional", 26340, 9882),
            ("EnterpriseSEval", 26100, 1742),
        ];
        assert_eq!(
            chosen(&host, &shipped, RULE),
            ["EnterpriseSEval-26100.1742", "Professional-26340.9882"]
        );
        // The same-build file is first even against the host's edition one build away.
        let shipped = [("Professional", 26101, 1), ("EnterpriseSEval", 26100, 1742)];
        assert_eq!(
            chosen(&host, &shipped, RULE),
            ["EnterpriseSEval-26100.1742", "Professional-26101.1"]
        );
    }

    #[test]
    fn nearest_below_and_above() {
        // The host of the design (26300.9974) and the two shipped baselines.
        let host = HostOs::new("Professional", 26300, 9974);
        let shipped = [
            ("EnterpriseSEval", 26100, 1742),
            ("Professional", 26340, 9882),
        ];
        assert_eq!(
            chosen(&host, &shipped, RULE),
            ["Professional-26340.9882", "EnterpriseSEval-26100.1742"]
        );
        // Farther ones on either side lose to nearer ones.
        let shipped = [
            ("Professional", 25900, 1),
            ("Professional", 26100, 1),
            ("Professional", 26340, 1),
            ("Professional", 26400, 1),
            ("Professional", 27000, 1),
        ];
        assert_eq!(
            chosen(&host, &shipped, RULE),
            [
                "Professional-26340.1",
                "Professional-26400.1",
                "Professional-26100.1"
            ]
        );
    }

    #[test]
    fn the_build_distance_limit() {
        let host = HostOs::new("Professional", 26100, 1);
        let shipped = [
            ("Professional", 27100, 1),
            ("Professional", 27101, 1),
            ("Professional", 25100, 1),
            ("Professional", 25099, 1),
            ("Professional", 19045, 5000),
        ];
        // Exactly 1000 away qualifies, 1001 does not; Windows 10 never stands in for Windows 11.
        assert_eq!(
            chosen(&host, &shipped, RULE),
            ["Professional-25100.1", "Professional-27100.1"]
        );
        let tight = NeighbourRule {
            max_build_distance: 0,
            max_count: 3,
        };
        assert!(chosen(&host, &shipped, tight).is_empty());
        assert_eq!(
            chosen(&host, &[("Core", 26100, 9)], tight),
            ["Core-26100.9"]
        );
    }

    #[test]
    fn ties_go_to_the_hosts_edition_then_the_nearer_revision() {
        let host = HostOs::new("Professional", 26200, 500);
        let shipped = [
            ("Enterprise", 26100, 500),
            ("PROFESSIONAL", 26300, 9000),
            ("Core", 26300, 400),
            ("Core", 26100, 450),
        ];
        // All four are 100 builds away.
        assert_eq!(
            chosen(&host, &shipped, RULE),
            [
                "PROFESSIONAL-26300.9000",
                "Enterprise-26100.500",
                "Core-26100.450"
            ]
        );
        // The order of the candidates does not matter.
        let mut reversed = shipped;
        reversed.reverse();
        assert_eq!(
            chosen(&host, &reversed, RULE),
            chosen(&host, &shipped, RULE)
        );
    }

    #[test]
    fn at_most_max_count_and_none() {
        let host = HostOs::new("Professional", 26100, 1);
        let shipped: Vec<(&str, u32, u32)> =
            (1..=6).map(|i| ("Professional", 26100 + i, 1)).collect();
        assert_eq!(chosen(&host, &shipped, RULE).len(), 3);
        assert_eq!(
            rank_neighbours(&host, shipped.iter().copied(), RULE).len(),
            6
        );
        let one = NeighbourRule {
            max_build_distance: 1000,
            max_count: 1,
        };
        assert_eq!(chosen(&host, &shipped, one), ["Professional-26101.1"]);
        let zero = NeighbourRule {
            max_build_distance: 1000,
            max_count: 0,
        };
        assert!(chosen(&host, &shipped, zero).is_empty());
        assert!(chosen(&host, &[], RULE).is_empty());
        assert!(chosen(&host, &[("Professional", 22631, 1)], RULE).is_empty());
    }

    #[test]
    fn shipped_names() {
        let p = parse_shipped_name;
        assert_eq!(
            p("Professional-26340.9882.tsv.gz"),
            Some(("Professional".to_owned(), 26340, 9882))
        );
        assert_eq!(
            p("Server_Core-1.2.TSV.GZ"),
            Some(("Server_Core".to_owned(), 1, 2))
        );
        for name in [
            "local-Professional-26100.9711-0123456789abcdef.tsv.gz",
            "local-Professional-26100.9711.tsv.gz",
            "Professional-26340.9882.tsv",
            "Professional-26340.tsv.gz",
            "Professional-26340.9882.1.tsv.gz",
            "Professional-+26340.9882.tsv.gz",
            "Professional-26340.-1.tsv.gz",
            "Professional-99999999999.1.tsv.gz",
            "-26340.9882.tsv.gz",
            "Pro fessional-26340.9882.tsv.gz",
            "Prö-26340.9882.tsv.gz",
            "26340.9882.tsv.gz",
            "view.json",
            "README.md",
            ".tsv.gz",
            "",
        ] {
            assert_eq!(p(name), None, "{name}");
        }
    }
}
