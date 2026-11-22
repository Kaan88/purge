//! The local baseline cache (BASELINE_LOCAL_DESIGN.md §5, package BL-CACHE; DECISIONS 2026-11-21).
//!
//! # Directory
//!
//! `%ProgramData%\Purge\baseline\`. [`LocalCache::open`] accepts it only when the file system source
//! says that the directory and every ancestor can be written by administrators and the system alone
//! (the rule of `DiskTableCache::open`). A directory that fails is not used and never repaired. Only
//! an elevated engine opens the cache writable; every write goes to a temporary name in the directory
//! and is renamed.
//!
//! Every file of the directory is reached through [`CacheFiles`], by its name: by path for the engine
//! ([`PathFiles`], behind the rule above), relative to the checked handle of the store's `baseline`
//! directory for the broker ([`LocalCache::with_files`]; DECISIONS 2026-11-22, "baseline checked").
//! The names, the formats and what a load decides are the same either way.
//!
//! # Parts, keyed per source
//!
//! The local baseline is stored as one text file per source, each in the local baseline file format
//! (`file.rs`) with that source's one `#src` line, so that a change of one source rebuilds that source
//! only (review BL-RM S7: an inbox Store app update must not discard the component manifests):
//!
//! | File | Source | Id made from |
//! |---|---|---|
//! | `local-<Edition>-<build>.<ubr>-s1-<id>.tsv.gz` | S1, component manifests (the expensive part) | count, total size and newest write time of `WinSxS\Manifests\*.manifest` |
//! | `local-<Edition>-<build>.<ubr>-s2-<id>.tsv.gz` | S2, the default profile's hive | size and write time of the hive file |
//! | `local-<Edition>-<build>.<ubr>-s4-<id>.tsv.gz` | S4, inbox package manifests | the sorted full names of the inbox packages of every user |
//!
//! Every id also covers the builder version ([`BUILDER_VERSION`]), and the file name the Windows
//! edition, build and revision. A part is used only when its name, its header (edition, build,
//! revision, builder version, id) and its single `#src` line agree with what the caller asks for and
//! its `#end` line holds; anything else is a miss. A new revision, a servicing change, an inbox
//! package update or a new builder version gives another id for the parts it touches, and only
//! those. After a store the two newest files of that source are kept.
//!
//! **S3 (`HKU\.DEFAULT`) is never stored.** Nothing an id could be made from says that the live hive
//! changed (review BL-RM S1), so a cached S3 part could be reused across a change no id covers. Each
//! load reads it again through the registry source ([`read_live_s3`], about 0.3 s) and judges its seal
//! then. An engine that is not elevated cannot read all of it, so its local baseline is incomplete
//! and its view has trust None; presence is still answered from everything it has.
//!
//! An engine that is not elevated also cannot list every user's packages, so it cannot compute the
//! S4 id. It takes the newest S4 part of this Windows and marks it unchecked (incomplete).
//!
//! # A stale part, for presence
//!
//! After a servicing change (a cumulative update, an inbox package update) the ids of the machine are
//! new and the build of the changed parts takes minutes. Until it has ended, a load takes the newest
//! part of that source of the same edition and build that this builder wrote, whatever its id and
//! revision ([`PartState::Stale`]), and marks its `#src` line incomplete with the reason. It is
//! still a list of keys Windows owned on this machine a moment ago, so it can say "this is Windows'
//! own" (L1: at the cost of a few keys of components that were removed); it cannot make the local
//! baseline complete, so the view's trust is None and nothing is inferred from it (L2). A stale part
//! still counts as missing for the build ([`LoadedLocal::missing`]).
//!
//! # The loaded local baseline
//!
//! [`LocalCache::load`] puts the parts together: the union of their hashed sets and of S3's, the four
//! `#src` lines (a missing part is a `failed` line, so the seal of design §3.4 says what is missing),
//! and a header whose source id is made from the ids of the parts used ([`PartIds::combined`]).
//!
//! # Derived form
//!
//! Parsing the text of the S1 part takes about three seconds, over the view's load budget. Beside it
//! the cache keeps `…-s1-<id>.sets`: the hashed sets ([`HashedSets`]) as little-endian binary, with
//! [`HashedSets::scheme`], the SHA-256 of the text file's bytes it was made from, and its own
//! SHA-256 at the end. A load hashes the text file, and takes the sets only when both hashes and the
//! scheme match; the header and the `#src` line are always read from the text file itself. Anything
//! else (no file, another scheme, a hash that does not match, sets out of order) means the text is
//! parsed and, in a writable cache, the derived file is written again. The derived file is never
//! trusted alone. The shipped neighbours get the same form (`shipped-<Edition>-<build>.<ubr>.sets`,
//! bound to the shipped file's bytes).
//!
//! # What a standard user cannot do
//!
//! Plant or change a part or a derived file: the directory rule. Make the engine take a part of
//! another Windows, builder or source state: name, header and id are compared. Remove records by
//! truncation: `#end`. The worst a failed check does is a miss, which costs presence (fewer blocks),
//! and absence is not inferred from an incomplete local baseline (L2).

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use purge_model::OsInfo;
use purge_source::filesystem::FileSystemSource;
use purge_source::local_baseline::{
    HiveEntry, HiveWalk, InboxPackages, LocalSources, ManifestIter, PROVISIONED_KEY,
    SYSTEM_DEFAULT_KEY, family_of_full_name, inbox_reason, walk_registry,
};
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{SourceError, SourceResult};
use sha2::{Digest, Sha256};

use super::Records;
use super::build::{BUILDER_VERSION, FileStamps, LocalPartFile, SealFloors, file_stamps, read_s3};
use super::file::{
    LocalBaseline, LocalHeader, LocalSource, MAX_FILE_BYTES, SourceLine, SourceStatus, hex,
};
use crate::baseline::{Baseline, BaselineError, HashedSets, RecordCounts, RecordParser};
use crate::baseline_view::{HostOs, Neighbour, NeighbourFile, NeighbourRule, select_neighbours};

/// The sources the cache stores a part of, in file order. S3 is read at every load.
pub const CACHED_PARTS: [LocalSource; 3] = [LocalSource::S1, LocalSource::S2, LocalSource::S4];

/// Files of one source kept after a store.
pub const KEEP_PARTS: usize = 2;

/// The first bytes of a derived sets file.
const SETS_MAGIC: &[u8; 12] = b"purge-sets1\n";
/// The largest derived sets file read: 256 MiB (a host's S1 sets are about 30 MB).
const MAX_SETS_BYTES: u64 = 256 << 20;
/// A temporary file older than this was left behind by a writer that is gone.
const TEMP_MAX_AGE: Duration = Duration::from_secs(600);

const PART_SUFFIX: &str = ".tsv.gz";
const SETS_SUFFIX: &str = ".sets";
const TEMP_SUFFIX: &str = ".tmp";

/// Distinguishes the temporary files of concurrent writers in one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------------------------------
// The files of the directory

/// How the cache reaches the files of its directory: every read, write, rename and removal of the
/// cache goes through this, by a file name in the directory, never by a path of its own.
///
/// [`LocalCache::open`] uses [`PathFiles`], by path, for the engine: its directory passed the
/// admin-only rule just before (the directory and every ancestor, owner included, no reparse point on
/// the chain), so a standard user cannot have planted anything in it. The broker gives
/// [`LocalCache::with_files`] its store's checked `baseline` directory instead, whose files are reached
/// relative to the checked handle without following anything (DECISIONS 2026-11-22, "baseline
/// checked").
pub trait CacheFiles: std::fmt::Debug + Send + Sync {
    /// The plain files of the directory (no directory, no link), with their last write times. A
    /// directory that cannot be listed lists nothing.
    fn list(&self) -> Vec<(String, SystemTime)>;
    /// The bytes of the file `name`: [`io::ErrorKind::NotFound`] when there is none,
    /// [`io::ErrorKind::InvalidData`] when it has more than `max` bytes.
    fn read(&self, name: &str, max: u64) -> io::Result<Vec<u8>>;
    /// Writes `bytes` to the new file `temp` and renames it over `name`.
    fn replace(&self, name: &str, temp: &str, bytes: &[u8]) -> io::Result<()>;
    /// Removes the file `name`.
    fn remove(&self, name: &str) -> io::Result<()>;
}

/// A rule a cache file must pass before [`PathFiles`] reads it ([`admin_only_file`] for an elevated
/// engine).
pub type FileRule = std::sync::Arc<dyn Fn(&Path) -> bool + Send + Sync>;

/// Whether the file at `path` can be changed by administrators and the system alone, it and every
/// ancestor (`purge_win::sid::is_admin_only_writable`: owner included, no reparse point on the chain),
/// and has one name: the rule an elevated engine reads a cache file by path under, as
/// `shipped_file_trusted` judges a shipped baseline. The directory rule does not cover a file: one
/// moved into the directory keeps its own owner and DACL, and a hard link shares them with its other
/// name.
pub fn admin_only_file(path: &Path) -> bool {
    purge_win::sid::is_admin_only_writable(path) == Ok(true)
        && purge_win::fs::metadata(path).is_ok_and(|m| m.n_links == 1 && m.reparse_tag == 0)
}

/// [`CacheFiles`] by path, in a directory that passed the admin-only rule ([`LocalCache::open`]).
/// With a [`FileRule`], a file that fails it is not read ([`io::ErrorKind::PermissionDenied`]; the
/// load takes it as a miss, so the view only loses presence).
#[derive(Clone)]
pub struct PathFiles {
    dir: PathBuf,
    rule: Option<FileRule>,
}

impl std::fmt::Debug for PathFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathFiles")
            .field("dir", &self.dir)
            .field("rule", &self.rule.is_some())
            .finish()
    }
}

impl PathFiles {
    /// The files of `dir`, read without a per-file rule.
    pub fn new(dir: &Path) -> PathFiles {
        PathFiles {
            dir: dir.to_path_buf(),
            rule: None,
        }
    }

    /// The files of `dir`; each must pass `rule` before it is read.
    pub fn with_rule(dir: &Path, rule: FileRule) -> PathFiles {
        PathFiles {
            dir: dir.to_path_buf(),
            rule: Some(rule),
        }
    }
}

impl CacheFiles for PathFiles {
    fn list(&self) -> Vec<(String, SystemTime)> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .filter_map(|e| {
                let modified = fs::metadata(e.path())
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                Some((e.file_name().into_string().ok()?, modified))
            })
            .collect()
    }

    fn read(&self, name: &str, max: u64) -> io::Result<Vec<u8>> {
        let path = self.dir.join(name);
        if let Some(rule) = &self.rule {
            // A missing file stays a missing file; one that is there must pass the rule.
            fs::symlink_metadata(&path)?;
            if !rule(&path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "a standard user can write it, it has more than one name or it is a link",
                ));
            }
        }
        read_capped(&path, max)
    }

    fn replace(&self, name: &str, temp: &str, bytes: &[u8]) -> io::Result<()> {
        let temp = self.dir.join(temp);
        let written = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, self.dir.join(name))
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temp);
        }
        written
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        fs::remove_file(self.dir.join(name))
    }
}

// ---------------------------------------------------------------------------------------------------
// Ids

/// The ids of the cached parts for the machine as it is now. `None`: the id cannot be computed, so
/// that part is a miss (or, for S4 with [`PartIds::s4_unverified`], taken unchecked).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartIds {
    /// S1: from the manifest directory's stamp.
    pub s1: Option<String>,
    /// S2: from the default hive's stamp.
    pub s2: Option<String>,
    /// S4: from the inbox package names of every user.
    pub s4: Option<String>,
    /// The engine is not elevated: it sees only its own account's packages and cannot compute the
    /// S4 id.
    pub s4_unverified: bool,
    /// What could not be read, for warnings.
    pub problems: Vec<String>,
}

impl PartIds {
    /// Reads the stamps through the sources and computes the ids: one listing of the manifest
    /// directory, the default hive's metadata and, when elevated, the package list (on another
    /// thread, at the same time).
    pub fn read(
        reg: &dyn RegistrySource,
        fs: &dyn FileSystemSource,
        sys: &dyn SystemSource,
    ) -> PartIds {
        let elevated = sys.elevated();
        let (files, packages) = std::thread::scope(|scope| {
            let files = scope.spawn(|| file_stamps(fs, reg, sys));
            let packages = elevated.then(|| inbox_package_names(reg, sys));
            let files = files
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            (files, packages)
        });
        let mut ids = match &packages {
            Some(Ok(names)) => PartIds::from_stamps(&files, Some(names)),
            _ => PartIds::from_stamps(&files, None),
        };
        match packages {
            None => ids.s4_unverified = true,
            Some(Err(e)) => ids
                .problems
                .push(format!("cannot list the installed packages: {e}")),
            Some(Ok(_)) => {}
        }
        ids
    }

    /// The ids of these stamps. `packages`: the inbox package full names of every user
    /// ([`inbox_package_names`]), or `None` when they are not known.
    pub fn from_stamps(files: &FileStamps, packages: Option<&[String]>) -> PartIds {
        let s1 = (files.manifests > 0).then(|| {
            part_id(
                LocalSource::S1,
                &format!(
                    "manifests\t{}\t{}\t{}\n",
                    files.manifests, files.manifest_bytes, files.manifest_newest_write
                ),
            )
        });
        let s2 = (files.hive_bytes > 0).then(|| {
            part_id(
                LocalSource::S2,
                &format!("hive\t{}\t{}\n", files.hive_bytes, files.hive_write),
            )
        });
        let s4 = packages.map(|names| {
            let mut names: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
            names.sort_unstable();
            names.dedup();
            let body: String = names.iter().map(|n| format!("package\t{n}\n")).collect();
            part_id(LocalSource::S4, &body)
        });
        PartIds {
            s1,
            s2,
            s4,
            s4_unverified: false,
            problems: files.problems.clone(),
        }
    }

    /// The id of one cached part.
    pub fn get(&self, source: LocalSource) -> Option<&str> {
        match source {
            LocalSource::S1 => self.s1.as_deref(),
            LocalSource::S2 => self.s2.as_deref(),
            LocalSource::S4 => self.s4.as_deref(),
            LocalSource::S3 | LocalSource::S5 => None,
        }
    }

    /// The source id of a local baseline put together from parts of these ids (`None`: that part
    /// is not in it): 16 hex digits. It is the header's source id and the fingerprint's `local_id`.
    pub fn combined(s1: Option<&str>, s2: Option<&str>, s4: Option<&str>) -> String {
        let mut sha = Sha256::new();
        sha.update(b"purge-local-parts/1\n");
        for (tag, id) in [("s1", s1), ("s2", s2), ("s4", s4)] {
            sha.update(format!("{tag}\t{}\n", id.unwrap_or("-")).as_bytes());
        }
        hex(&sha.finalize()[..8])
    }
}

/// The id of one part: 16 hex digits over the source, the builder version and the source's stamp.
fn part_id(source: LocalSource, stamp: &str) -> String {
    let mut sha = Sha256::new();
    sha.update(b"purge-local-part/1\n");
    sha.update(format!("{}\n{BUILDER_VERSION}\n", source.tag()).as_bytes());
    sha.update(stamp.as_bytes());
    hex(&sha.finalize()[..8])
}

/// The full names of the inbox packages, by the rule the S4 reader applies
/// (`purge_source::local_baseline::collect_inbox_packages`), without reading a manifest. The list
/// is every user's only when the engine is elevated.
pub fn inbox_package_names(
    reg: &dyn RegistrySource,
    sys: &dyn SystemSource,
) -> SourceResult<Vec<String>> {
    let listed = sys.packages()?;
    let provisioned = reg
        .subkeys(PROVISIONED_KEY)
        .map(|names| {
            names
                .iter()
                .filter_map(|n| family_of_full_name(n))
                .collect()
        })
        .unwrap_or_default();
    let mut names: Vec<String> = listed
        .iter()
        .filter(|p| inbox_reason(p, &provisioned).is_some())
        .map(|p| p.full_name.clone())
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

// ---------------------------------------------------------------------------------------------------
// S3, live

/// Local sources that have only S3: `HKU\.DEFAULT` through a registry source.
struct LiveS3<'a>(&'a dyn RegistrySource);

impl LocalSources for LiveS3<'_> {
    fn manifests(&self) -> SourceResult<ManifestIter<'_>> {
        Err(SourceError::NotCaptured)
    }

    fn default_hive(&self, _: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
        Err(SourceError::NotCaptured)
    }

    fn system_default(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
        walk_registry(self.0, SYSTEM_DEFAULT_KEY, visit)
    }

    fn inbox_packages(&self) -> SourceResult<InboxPackages> {
        Err(SourceError::NotCaptured)
    }
}

/// S3 as it is now, read through `reg` on the caller's thread: its `#src` line (sealed with the
/// design's floors) and its records. See the module documentation for why it is never cached.
pub fn read_live_s3(reg: &dyn RegistrySource) -> (SourceLine, Records) {
    read_s3(&LiveS3(reg), &SealFloors::default())
}

// ---------------------------------------------------------------------------------------------------
// The cache

/// How one cached part answered a load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartState {
    /// Used. `derived`: its sets came from the derived binary form, not from parsing the text.
    Hit {
        /// The sets came from the derived form.
        derived: bool,
    },
    /// S4 only: the newest part of this Windows, used without checking its id (not elevated).
    Unverified,
    /// No part for the id asked for, and an older part of the same edition and build is used in its
    /// place for presence only: its `#src` line is incomplete, so the local baseline is incomplete
    /// and the view's trust is None. The part still has to be built.
    Stale,
    /// No usable part for the id asked for.
    Missing,
}

impl PartState {
    /// Whether a build has to make this part: there is none for the machine as it is now.
    pub fn needs_build(self) -> bool {
        matches!(self, PartState::Missing | PartState::Stale)
    }
}

/// What [`LocalCache::load`] found.
#[derive(Debug, Clone)]
pub struct LoadedLocal {
    /// The local baseline put together from the parts and the live S3, or `None` when no part is
    /// usable.
    pub local: Option<LocalBaseline>,
    /// S1, S2 and S4, in that order.
    pub parts: [(LocalSource, PartState); 3],
    /// What was found unusable, one line each.
    pub notes: Vec<String>,
}

impl LoadedLocal {
    /// The cached sources that have no part for the machine as it is now (what a build has to
    /// make): the missing ones and those answered from a stale part.
    pub fn missing(&self) -> Vec<LocalSource> {
        self.parts
            .iter()
            .filter(|(_, state)| state.needs_build())
            .map(|(source, _)| *source)
            .collect()
    }
}

/// One part as loaded.
struct Part {
    header: LocalHeader,
    line: SourceLine,
    sets: HashedSets,
    derived: bool,
    /// Not the part of the machine as it is now ([`PartState::Stale`]).
    stale: bool,
}

/// The cache directory. See the module documentation.
#[derive(Debug, Clone)]
pub struct LocalCache {
    dir: PathBuf,
    files: std::sync::Arc<dyn CacheFiles>,
    writable: bool,
}

impl LocalCache {
    /// The cache in `dir`, or `None` unless `fs` says that only administrators (and the system) can
    /// write `dir` and every ancestor; an error from `fs` (the directory missing, access denied, a
    /// path that is not UTF-8) is `None` as well, and so is a directory this process does not see
    /// or one that is itself a link or junction, whatever `fs` says about it. The directory is not
    /// created here.
    ///
    /// `writable`: the engine is elevated and may store. A writable cache removes the temporary
    /// files a writer left behind.
    pub fn open(dir: &Path, fs: &dyn FileSystemSource, writable: bool) -> Option<LocalCache> {
        Self::open_with_rule(dir, fs, writable, None)
    }

    /// [`LocalCache::open`], reading each file only when it passes `rule` ([`PathFiles::with_rule`]):
    /// the elevated live engine passes [`admin_only_file`].
    pub fn open_with_rule(
        dir: &Path,
        fs: &dyn FileSystemSource,
        writable: bool,
        rule: Option<FileRule>,
    ) -> Option<LocalCache> {
        let path = dir.to_str()?;
        // The directory itself is asked without following it: `Path::is_dir` would say yes to a
        // junction that leads somewhere else.
        let plain_dir = fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir());
        if fs.is_admin_only_writable(path) != Ok(true) || !plain_dir {
            return None;
        }
        let files = match rule {
            Some(rule) => PathFiles::with_rule(dir, rule),
            None => PathFiles::new(dir),
        };
        Some(Self::with_files(dir, std::sync::Arc::new(files), writable))
    }

    /// The cache whose files `files` reaches, in the directory `dir` (named in messages and in the
    /// path [`LocalCache::store_part`] returns; never opened by this value). The caller vouches for the
    /// directory: the broker passes its store's checked `baseline` directory. A writable cache removes
    /// the temporary files a writer left behind.
    pub fn with_files(dir: &Path, files: std::sync::Arc<dyn CacheFiles>, writable: bool) -> Self {
        let cache = LocalCache {
            dir: dir.to_path_buf(),
            files,
            writable,
        };
        if writable {
            cache.sweep_temporary(TEMP_MAX_AGE);
        }
        cache
    }

    /// The cache directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether this engine may store.
    pub fn writable(&self) -> bool {
        self.writable
    }

    /// Puts the local baseline of `os` together from the cached parts of `ids` and from `s3` (read
    /// now, [`read_live_s3`]). See the module documentation.
    pub fn load(&self, os: &OsInfo, ids: &PartIds, s3: (SourceLine, Records)) -> LoadedLocal {
        let mut notes = Vec::new();
        let mut parts = CACHED_PARTS.map(|source| (source, PartState::Missing));
        let mut loaded: Vec<Option<Part>> = Vec::new();
        let Some(os_tag) = os_tag(os) else {
            return LoadedLocal {
                local: None,
                parts,
                notes: vec!["the Windows edition is unknown; the cache is not used".into()],
            };
        };
        // The three parts are read at the same time: the S1 part is most of the cost.
        let read: Vec<(Option<Part>, PartState, Vec<String>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = CACHED_PARTS
                .iter()
                .map(|&source| {
                    let os_tag = os_tag.as_str();
                    scope.spawn(move || {
                        let mut notes = Vec::new();
                        let (part, state) = self.load_source(os, os_tag, source, ids, &mut notes);
                        (part, state, notes)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                })
                .collect()
        });
        for (slot, (part, state, mut part_notes)) in parts.iter_mut().zip(read) {
            slot.1 = state;
            notes.append(&mut part_notes);
            loaded.push(part);
        }
        if loaded.iter().all(Option::is_none) {
            return LoadedLocal {
                local: None,
                parts,
                notes,
            };
        }

        // A stale part goes into the id as what it is, so the id of a local baseline that holds one
        // is never the id of the complete one it was once part of.
        let used: Vec<Option<String>> = loaded
            .iter()
            .map(|part| {
                part.as_ref().map(|p| {
                    if p.stale {
                        format!("stale:{}", p.header.source_id)
                    } else {
                        p.header.source_id.clone()
                    }
                })
            })
            .collect();
        let used_id = |i: usize| used[i].as_deref();
        let source_id = PartIds::combined(used_id(0), used_id(1), used_id(2));
        // The header's time and computer are the S1 part's when there is one.
        let first = loaded.iter().flatten().next().map(|p| p.header.clone());
        let Some(first) = first else {
            return LoadedLocal {
                local: None,
                parts,
                notes,
            };
        };
        let header = LocalHeader {
            built_at: first.built_at,
            computer: first.computer,
            edition: os.edition.clone(),
            build: os.build,
            ubr: os.ubr,
            builder_version: BUILDER_VERSION.to_owned(),
            source_id,
        };

        let (s3_line, s3_records) = s3;
        let mut sets = HashedSets::default();
        let mut lines: Vec<SourceLine> = Vec::with_capacity(4);
        let mut s3_line = Some(s3_line);
        for (&source, part) in CACHED_PARTS.iter().zip(loaded) {
            if source == LocalSource::S4
                && let Some(line) = s3_line.take()
            {
                lines.push(line);
            }
            match part {
                Some(part) => {
                    union(&mut sets, part.sets);
                    lines.push(part.line);
                }
                None => lines.push(missing_line(source)),
            }
        }
        match hashed_sets_of(&s3_records) {
            Ok(s3_sets) => union(&mut sets, s3_sets),
            Err(e) => {
                notes.push(format!(
                    "the records of HKU\\.DEFAULT could not be hashed ({e})"
                ));
                if let Some(line) = lines.iter_mut().find(|l| l.source == LocalSource::S3) {
                    line.status = SourceStatus::Failed;
                    line.reasons.push("its records could not be hashed".into());
                }
            }
        }
        let local = match LocalBaseline::from_hashed_sets(header, lines, sets) {
            Ok(local) => Some(local),
            Err(e) => {
                notes.push(format!("the cached parts could not be put together ({e})"));
                None
            }
        };
        LoadedLocal {
            local,
            parts,
            notes,
        }
    }

    /// Whether the cache holds a usable part of `source` with this id (the check a load makes).
    pub fn has_part(&self, os: &OsInfo, source: LocalSource, id: &str) -> bool {
        os_tag(os).is_some_and(|tag| {
            self.load_part(
                os,
                &part_name(&tag, source, id),
                source,
                Some(id),
                false,
                &mut Vec::new(),
            )
            .is_some()
        })
    }

    fn load_source(
        &self,
        os: &OsInfo,
        os_tag: &str,
        source: LocalSource,
        ids: &PartIds,
        notes: &mut Vec<String>,
    ) -> (Option<Part>, PartState) {
        if let Some(id) = ids.get(source) {
            let name = part_name(os_tag, source, id);
            return match self.load_part(os, &name, source, Some(id), false, notes) {
                Some(part) => {
                    let derived = part.derived;
                    (Some(part), PartState::Hit { derived })
                }
                None => match self.load_stale(os, source, Some(id), notes) {
                    Some(part) => (Some(part), PartState::Stale),
                    None => (None, PartState::Missing),
                },
            };
        }
        if source == LocalSource::S4 && ids.s4_unverified {
            // Not elevated: the newest S4 part of this Windows, marked as not checked.
            let newest = self
                .part_files(source)
                .into_iter()
                .find(|f| f.name.starts_with(&format!("local-{os_tag}-")));
            if let Some(file) = newest
                && let Some(mut part) = self.load_part(os, &file.name, source, None, false, notes)
            {
                if part.line.status == SourceStatus::Ok {
                    part.line.status = SourceStatus::Incomplete;
                }
                part.line.reasons.push(
                    "not checked against the installed packages (the engine is not elevated)"
                        .into(),
                );
                return (Some(part), PartState::Unverified);
            }
        }
        // The id is unknown (the source could not be stamped): the newest part, for presence.
        match self.load_stale(os, source, None, notes) {
            Some(part) => (Some(part), PartState::Stale),
            None => (None, PartState::Missing),
        }
    }

    /// The newest part of `source` for the edition and build of `os`, other than the part of the id
    /// `current` (which the caller found missing or unusable; `None`: the id is unknown), marked
    /// for presence only: its `#src` line is incomplete and says why. Any revision of that build
    /// counts, so the part made before a cumulative update is found after it. A part of another
    /// edition, another build or another builder version is never taken.
    fn load_stale(
        &self,
        os: &OsInfo,
        source: LocalSource,
        current: Option<&str>,
        notes: &mut Vec<String>,
    ) -> Option<Part> {
        let tried = os_tag(os)
            .zip(current)
            .map(|(tag, id)| part_name(&tag, source, id));
        // The edition is plain (`os_tag` said so before any part was looked for).
        let same_build = format!("local-{}-{}.", os.edition, os.build);
        for file in self.part_files(source) {
            if !file.name.starts_with(&same_build) || tried.as_deref() == Some(file.name.as_str()) {
                continue;
            }
            // What makes an old file unusable is not worth a line per load.
            let Some(mut part) =
                self.load_part(os, &file.name, source, None, true, &mut Vec::new())
            else {
                continue;
            };
            part.stale = true;
            if part.line.status == SourceStatus::Ok {
                part.line.status = SourceStatus::Incomplete;
            }
            let now = current.map_or_else(
                || "the id of this Windows as it is now is unknown".to_owned(),
                |id| format!("this Windows now has id {id}"),
            );
            let h = &part.header;
            part.line.reasons.push(format!(
                "stale: the part with id {} of {}-{}.{} is used for presence only, {now}",
                h.source_id, h.edition, h.build, h.ubr
            ));
            notes.push(format!(
                "{} is used for presence only until the {source} part of {} is built ({now})",
                file.name,
                os.baseline_name()
            ));
            return Some(part);
        }
        None
    }
    /// Loads the part file `name`: its bytes hashed, then the derived sets when they are bound to
    /// these bytes (S1), else the text parsed. `id`: the id the header must carry (`None`: the one
    /// in the name). `any_revision`: the header may name another revision of the build of `os`
    /// ([`LocalCache::load_stale`]).
    fn load_part(
        &self,
        os: &OsInfo,
        name: &str,
        source: LocalSource,
        id: Option<&str>,
        any_revision: bool,
        notes: &mut Vec<String>,
    ) -> Option<Part> {
        let bytes = match self.files.read(name, MAX_FILE_BYTES as u64) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => {
                notes.push(format!("{name} cannot be read ({e})"));
                return None;
            }
        };
        let id = match id {
            Some(id) => id,
            None => id_in_name(name)?,
        };
        let sha: [u8; 32] = Sha256::digest(&bytes).into();
        let sets_file = sets_name(name);
        let mut bytes = Some(bytes);
        if source == LocalSource::S1
            && let Some((header, lines)) = bytes.as_deref().and_then(read_head)
            && part_matches(&header, &lines, os, source, id, any_revision)
        {
            // The text is not held while the sets are read (the load's peak memory); it is read
            // again, and must be the same bytes, when the sets turn out not to be its.
            bytes = None;
            if let Some(sets) = self.read_sets(&sets_file, &sha) {
                let line = lines.into_iter().next()?;
                return Some(Part {
                    header,
                    line,
                    sets,
                    derived: true,
                    stale: false,
                });
            }
        }
        let bytes = match bytes {
            Some(bytes) => bytes,
            None => {
                let again = self.files.read(name, MAX_FILE_BYTES as u64).ok()?;
                if Sha256::digest(&again).as_slice() != sha {
                    notes.push(format!("{name} changed while it was read"));
                    return None;
                }
                again
            }
        };
        let local = match LocalBaseline::from_bytes(&bytes) {
            Ok(local) => local,
            Err(e) => {
                notes.push(format!("{name} is unusable ({e})"));
                return None;
            }
        };
        if !part_matches(
            local.header(),
            local.sources(),
            os,
            source,
            id,
            any_revision,
        ) {
            notes.push(format!(
                "{name} is not the {source} part of {} with id {id}",
                os.baseline_name()
            ));
            return None;
        }
        let header = local.header().clone();
        let line = local.sources().first()?.clone();
        let sets = local.into_hashed_sets();
        if source == LocalSource::S1 && self.writable {
            // Failing to write the derived form costs the next load its time, nothing else.
            let _ = self.write_atomic(&sets_name(name), &encode_sets(&sha, &sets));
        }
        Some(Part {
            header,
            line,
            sets,
            derived: false,
            stale: false,
        })
    }

    /// Stores a built part: the text file is read back first (the check a load makes), written
    /// through a temporary file and renamed; for S1 the derived sets are written beside it; then
    /// older files of that source are removed ([`KEEP_PARTS`] stay). Only a writable cache stores.
    pub fn store_part(&self, os: &OsInfo, part: &LocalPartFile) -> io::Result<PathBuf> {
        let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidInput, why);
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the local baseline cache is written only by an elevated engine",
            ));
        }
        let id = part.header.source_id.as_str();
        if !CACHED_PARTS.contains(&part.source) || !plain_id(id) {
            return Err(invalid(format!(
                "{} with id {id:?} is not a part of the cache",
                part.source
            )));
        }
        let os_tag = os_tag(os).ok_or_else(|| invalid("the Windows edition is unknown".into()))?;
        let local = LocalBaseline::from_bytes(&part.bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if !part_matches(local.header(), local.sources(), os, part.source, id, false) {
            return Err(invalid(format!(
                "the part is not the {} part of {} with id {id}",
                part.source,
                os.baseline_name()
            )));
        }
        let name = part_name(&os_tag, part.source, id);
        self.write_atomic(&name, &part.bytes)?;
        if part.source == LocalSource::S1 {
            let sha: [u8; 32] = Sha256::digest(&part.bytes).into();
            let sets = local.into_hashed_sets();
            let _ = self.write_atomic(&sets_name(&name), &encode_sets(&sha, &sets));
        }
        self.prune(part.source, &name);
        Ok(self.dir.join(name))
    }

    /// A shipped baseline as a neighbour: from its derived sets when they are bound to the file's
    /// bytes, else parsed from the file (and, in a writable cache, the derived sets are written).
    /// The checks of [`Neighbour::load`] hold either way: the derived form is written only for bytes
    /// that parsed and whose header names what the file name names.
    pub fn neighbour(&self, file: &NeighbourFile) -> Result<Neighbour, BaselineError> {
        let bytes = fs::read(&file.path)?;
        let sha: [u8; 32] = Sha256::digest(&bytes).into();
        if let Some(sets) = self.read_sets(&shipped_sets_name(file), &sha)
            && let Ok(n) = Neighbour::from_hashed_sets(&file.edition, file.build, file.ubr, sets)
        {
            return Ok(n);
        }
        let neighbour = neighbour_from_bytes(file, &bytes)?;
        if !self.writable {
            return Ok(neighbour);
        }
        let sets = neighbour.into_hashed_sets();
        let _ = self.write_atomic(&shipped_sets_name(file), &encode_sets(&sha, &sets));
        Neighbour::from_hashed_sets(&file.edition, file.build, file.ubr, sets)
            .map_err(|e| BaselineError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))
    }

    /// Removes the derived forms of shipped baselines other than `keep` (a writable cache only).
    fn prune_shipped(&self, keep: &[String]) {
        if !self.writable {
            return;
        }
        for (name, _) in self.files.list() {
            if name.starts_with("shipped-") && name.ends_with(SETS_SUFFIX) && !keep.contains(&name)
            {
                let _ = self.files.remove(&name);
            }
        }
    }

    /// The sets of the derived file `name` when it is bound to `bound`; `None` for a missing or bad
    /// file (the caller parses the text).
    fn read_sets(&self, name: &str, bound: &[u8; 32]) -> Option<HashedSets> {
        decode_sets(&self.files.read(name, MAX_SETS_BYTES).ok()?, bound)
    }

    /// The part files of one source (any Windows), newest first.
    fn part_files(&self, source: LocalSource) -> Vec<PartFileEntry> {
        let marker = format!("-{}-", source.tag().to_ascii_lowercase());
        let mut found: Vec<PartFileEntry> = self
            .files
            .list()
            .into_iter()
            .filter(|(name, _)| {
                name.starts_with("local-")
                    && name.ends_with(PART_SUFFIX)
                    && id_in_name(name).is_some()
                    && name[..name.len() - PART_SUFFIX.len() - 16].ends_with(&marker)
            })
            .map(|(name, modified)| PartFileEntry { name, modified })
            .collect();
        found.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| a.name.cmp(&b.name))
        });
        found
    }

    /// Keeps `just_stored` and the newest other files of `source` up to [`KEEP_PARTS`]; removes the
    /// rest, and every derived file whose text file is gone.
    fn prune(&self, source: LocalSource, just_stored: &str) {
        let mut kept = 1usize;
        for file in self.part_files(source) {
            if file.name == just_stored {
                continue;
            }
            if kept < KEEP_PARTS {
                kept += 1;
            } else {
                let _ = self.files.remove(&file.name);
            }
        }
        let files = self.files.list();
        for (name, _) in &files {
            if let Some(stem) = name.strip_suffix(SETS_SUFFIX)
                && name.starts_with("local-")
            {
                let text = format!("{stem}{PART_SUFFIX}");
                if !files.iter().any(|(other, _)| *other == text) {
                    let _ = self.files.remove(name);
                }
            }
        }
    }

    /// Removes temporary files older than `max_age`: a writer that crashed left them, and nothing
    /// ever reads one.
    fn sweep_temporary(&self, max_age: Duration) {
        let now = SystemTime::now();
        for (name, modified) in self.files.list() {
            if !name.ends_with(TEMP_SUFFIX) {
                continue;
            }
            if now.duration_since(modified).is_ok_and(|age| age >= max_age) {
                let _ = self.files.remove(&name);
            }
        }
    }

    /// Writes `bytes` to a temporary name in the directory and renames it to `name`.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if !self.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the local baseline cache is written only by an elevated engine",
            ));
        }
        self.files.replace(name, &cache_temp_name(name), bytes)
    }
}

/// The temporary name a write of `name` goes to: `<name>.<pid>.<n>.tmp`, `n` counting this process's
/// writes.
pub fn cache_temp_name(name: &str) -> String {
    format!(
        "{name}.{}.{}{TEMP_SUFFIX}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The name of the `source` part of `os` with this id (`None` for an edition the cache does not
/// name), and the name of its derived sets file: what the cache stores, for the store's tests.
pub fn part_file_names(os: &OsInfo, source: LocalSource, id: &str) -> Option<(String, String)> {
    let part = part_name(&os_tag(os)?, source, id);
    let sets = sets_name(&part);
    Some((part, sets))
}

/// The name of the derived sets file of a shipped neighbour.
pub fn shipped_sets_file_name(file: &NeighbourFile) -> String {
    shipped_sets_name(file)
}

struct PartFileEntry {
    name: String,
    modified: SystemTime,
}

/// Selects and loads the neighbours of `host` from the shipped directory `dir`, as
/// `baseline_view::load_neighbours` does (the best `rule.max_count` files in parallel, an unusable
/// one skipped with a warning and the next on the list tried in its place), but through the cache's
/// derived forms when there is a cache.
pub fn load_neighbours(
    cache: Option<&LocalCache>,
    dir: &Path,
    host: &HostOs,
    rule: NeighbourRule,
    warnings: &mut Vec<String>,
) -> Vec<Neighbour> {
    let all = NeighbourRule {
        max_count: usize::MAX,
        ..rule
    };
    let files = match select_neighbours(dir, host, all) {
        Ok(files) => files,
        Err(e) => {
            warnings.push(format!(
                "baseline: cannot list {} ({e}); no neighbouring baseline is used",
                dir.display()
            ));
            return Vec::new();
        }
    };
    let load = |file: &NeighbourFile| match cache {
        Some(cache) => cache.neighbour(file),
        None => Neighbour::load(file),
    };
    let (first, rest) = files.split_at(rule.max_count.min(files.len()));
    let loaded: Vec<Result<Neighbour, BaselineError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = first
            .iter()
            .map(|file| scope.spawn(move || load(file)))
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
    let mut used = Vec::new();
    let mut results: Vec<(&NeighbourFile, Result<Neighbour, BaselineError>)> =
        first.iter().zip(loaded).collect();
    let mut rest = rest.iter();
    let mut at = 0;
    while at < results.len() {
        let (file, result) = std::mem::replace(
            &mut results[at],
            (&files[0], Err(BaselineError::BadHeader(String::new()))),
        );
        at += 1;
        match result {
            Ok(n) => {
                used.push(shipped_sets_name(file));
                out.push(n);
            }
            Err(e) => {
                warnings.push(format!(
                    "baseline: the neighbouring baseline {} is unusable ({e}); it is skipped",
                    file.path.display()
                ));
                // The next one on the list takes its place.
                if let Some(next) = rest.next() {
                    results.push((next, load(next)));
                }
            }
        }
    }
    if let Some(cache) = cache {
        cache.prune_shipped(&used);
    }
    out
}

fn neighbour_from_bytes(file: &NeighbourFile, bytes: &[u8]) -> Result<Neighbour, BaselineError> {
    let baseline = Baseline::from_bytes(bytes)?;
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
    Ok(Neighbour::from_baseline(baseline))
}

// ---------------------------------------------------------------------------------------------------
// Names

/// `<Edition>-<build>.<ubr>` for file names, or `None` unless the edition is letters, digits and `_`
/// (the rule of the exact loader).
fn os_tag(os: &OsInfo) -> Option<String> {
    let plain = !os.edition.is_empty()
        && os
            .edition
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    plain.then(|| format!("{}-{}.{}", os.edition, os.build, os.ubr))
}

fn plain_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn part_name(os_tag: &str, source: LocalSource, id: &str) -> String {
    format!(
        "local-{os_tag}-{}-{id}{PART_SUFFIX}",
        source.tag().to_ascii_lowercase()
    )
}

/// The 16 hex digits before the suffix of a part file's name.
fn id_in_name(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(PART_SUFFIX)?;
    let at = stem.len().checked_sub(16)?;
    let id = stem.get(at..)?;
    (plain_id(id) && stem[..at].ends_with('-')).then_some(id)
}

/// The derived file's name for a part file's name.
fn sets_name(part: &str) -> String {
    format!(
        "{}{SETS_SUFFIX}",
        part.strip_suffix(PART_SUFFIX).unwrap_or(part)
    )
}

fn shipped_sets_name(file: &NeighbourFile) -> String {
    format!("shipped-{}{SETS_SUFFIX}", file.name())
}

fn missing_line(source: LocalSource) -> SourceLine {
    SourceLine {
        source,
        status: SourceStatus::Failed,
        items: 0,
        records: 0,
        skipped: 0,
        reasons: vec!["no cached part for this Windows as it is now".into()],
        facts: Vec::new(),
    }
}

/// Whether a part's header and `#src` lines are those of the `source` part of `os` with this id,
/// written by this builder. `any_revision`: the revision is not compared (a stale part).
fn part_matches(
    header: &LocalHeader,
    lines: &[SourceLine],
    os: &OsInfo,
    source: LocalSource,
    id: &str,
    any_revision: bool,
) -> bool {
    header.edition.eq_ignore_ascii_case(&os.edition)
        && header.build == os.build
        && (any_revision || header.ubr == os.ubr)
        && header.builder_version == BUILDER_VERSION
        && header.source_id == id
        && matches!(lines, [one] if one.source == source)
}

// ---------------------------------------------------------------------------------------------------
// Reading

fn read_capped(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{len} bytes, more than {max}"),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    Ok(bytes)
}

/// The header and the `#src` lines at the head of a local baseline file (gzip), without reading its
/// records. `None` when the head is not a local baseline's.
fn read_head(bytes: &[u8]) -> Option<(LocalHeader, Vec<SourceLine>)> {
    const MAX_HEAD_LINE: u64 = 1 << 20;
    let mut reader = BufReader::new(flate2::bufread::MultiGzDecoder::new(bytes));
    let mut line = Vec::new();
    let mut next = |line: &mut Vec<u8>| -> Option<bool> {
        line.clear();
        let n = (&mut reader)
            .take(MAX_HEAD_LINE)
            .read_until(b'\n', line)
            .ok()?;
        Some(n > 0 && line.pop() == Some(b'\n'))
    };
    if !next(&mut line)? {
        return None;
    }
    let header = LocalHeader::parse(std::str::from_utf8(&line).ok()?).ok()?;
    let mut lines = Vec::new();
    while next(&mut line)? && line.starts_with(b"#src\t") {
        lines.push(SourceLine::parse(std::str::from_utf8(&line).ok()?)?);
    }
    Some((header, lines))
}

/// The hashed sets of text records, made with the loader's record parser.
fn hashed_sets_of(records: &Records) -> Result<HashedSets, BaselineError> {
    let mut text = Vec::new();
    records.write_records(&mut text)?;
    let mut out = Baseline::empty("", 0, 0, "", "", "local");
    let mut parser = RecordParser::new();
    let mut line_no = 0u64;
    for line in text.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        line_no += 1;
        parser.add(&mut out, line, line_no)?;
    }
    out.finish_sets();
    Ok(out.into_hashed_sets())
}

/// Adds every hash of `more` to `into` (both strictly ascending, and so is the result).
fn union(into: &mut HashedSets, more: HashedSets) {
    fn merge(a: &mut Vec<u64>, b: Vec<u64>) {
        if a.is_empty() {
            *a = b;
            return;
        }
        if b.is_empty() {
            return;
        }
        let left = std::mem::take(a);
        let mut out = Vec::with_capacity(left.len() + b.len());
        let (mut i, mut j) = (0, 0);
        while i < left.len() && j < b.len() {
            match left[i].cmp(&b[j]) {
                std::cmp::Ordering::Less => {
                    out.push(left[i]);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    out.push(b[j]);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    out.push(left[i]);
                    i += 1;
                    j += 1;
                }
            }
        }
        out.extend_from_slice(&left[i..]);
        out.extend_from_slice(&b[j..]);
        *a = out;
    }
    into.counts = RecordCounts {
        keys: into.counts.keys + more.counts.keys,
        values: into.counts.values + more.counts.values,
        dirs: into.counts.dirs + more.counts.dirs,
        files: into.counts.files + more.counts.files,
    };
    merge(&mut into.keys, more.keys);
    merge(&mut into.values, more.values);
    merge(&mut into.dirs, more.dirs);
    merge(&mut into.files, more.files);
    merge(&mut into.leaves, more.leaves);
    merge(&mut into.parts, more.parts);
}

// ---------------------------------------------------------------------------------------------------
// The derived form

/// The derived file of `sets`, bound to the file whose SHA-256 is `bound`:
/// magic, scheme (length and text), `bound`, the four record counts, the six sets (length and
/// little-endian hashes), then the SHA-256 of everything before.
fn encode_sets(bound: &[u8; 32], sets: &HashedSets) -> Vec<u8> {
    let all = [
        &sets.keys,
        &sets.values,
        &sets.dirs,
        &sets.files,
        &sets.leaves,
        &sets.parts,
    ];
    let scheme = HashedSets::scheme();
    let hashes: usize = all.iter().map(|s| s.len()).sum();
    let mut out = Vec::with_capacity(160 + scheme.len() + 8 * hashes);
    out.extend_from_slice(SETS_MAGIC);
    out.extend_from_slice(&u32::try_from(scheme.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(scheme.as_bytes());
    out.extend_from_slice(bound);
    let c = sets.counts;
    for n in [c.keys, c.values, c.dirs, c.files] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    for set in all {
        out.extend_from_slice(&(set.len() as u64).to_le_bytes());
        for h in set {
            out.extend_from_slice(&h.to_le_bytes());
        }
    }
    let sha = Sha256::digest(&out);
    out.extend_from_slice(&sha);
    out
}

/// Reads a derived file back. `None` unless its own hash holds, it was made with this build's
/// scheme, it is bound to `bound`, nothing is left over and every set is strictly ascending.
fn decode_sets(bytes: &[u8], bound: &[u8; 32]) -> Option<HashedSets> {
    struct Cursor<'a>(&'a [u8]);
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let (head, tail) = self.0.split_at_checked(n)?;
            self.0 = tail;
            Some(head)
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
        }
        fn set(&mut self) -> Option<Vec<u64>> {
            let len = usize::try_from(self.u64()?).ok()?;
            let raw = self.take(len.checked_mul(8)?)?;
            Some(
                raw.chunks_exact(8)
                    .map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
                    .collect(),
            )
        }
    }
    let (body, own) = bytes.split_at_checked(bytes.len().checked_sub(32)?)?;
    if Sha256::digest(body).as_slice() != own {
        return None;
    }
    let mut c = Cursor(body);
    if c.take(SETS_MAGIC.len())? != SETS_MAGIC {
        return None;
    }
    let scheme_len = u32::from_le_bytes(c.take(4)?.try_into().ok()?);
    if c.take(usize::try_from(scheme_len).ok()?)? != HashedSets::scheme().as_bytes() {
        return None;
    }
    if c.take(32)? != bound {
        return None;
    }
    let counts = RecordCounts {
        keys: c.u64()?,
        values: c.u64()?,
        dirs: c.u64()?,
        files: c.u64()?,
    };
    let sets = HashedSets {
        counts,
        keys: c.set()?,
        values: c.set()?,
        dirs: c.set()?,
        files: c.set()?,
        leaves: c.set()?,
        parts: c.set()?,
    };
    if !c.0.is_empty() {
        return None;
    }
    sets.check().ok()?;
    Some(sets)
}

#[cfg(test)]
mod tests {
    use purge_source::fixture::Fixture;
    use purge_source::types::{PackageInfo, PackageSignatureKind};

    use super::super::build::tests::{SHELL, machine, options, os, with_hive};
    use super::super::build::{BuildControl, build, build_part};
    use super::super::file::encode;
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("purge-local-cache-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A file system that says `dir` is (or is not) admin-only writable.
    fn fs_saying(dir: &Path, admin_only: bool) -> Fixture {
        let d = dir.to_str().unwrap();
        Fixture::builder()
            .dir(d)
            .admin_only_writable(d, admin_only)
            .build()
    }

    fn cache(dir: &Path, writable: bool) -> LocalCache {
        LocalCache::open(dir, &fs_saying(dir, true), writable).unwrap()
    }

    fn ok_line(source: LocalSource) -> SourceLine {
        SourceLine {
            source,
            status: SourceStatus::Ok,
            items: 1,
            records: 1,
            skipped: 0,
            reasons: Vec::new(),
            facts: vec![("unreadable".into(), "0".into())],
        }
    }

    /// A part of `os` holding `keys`, written by `builder`.
    fn part_of(
        os: &OsInfo,
        source: LocalSource,
        id: &str,
        keys: &[&str],
        builder: &str,
    ) -> LocalPartFile {
        let header = LocalHeader {
            built_at: "2026-11-21T00:00:00Z".into(),
            computer: "PC".into(),
            edition: os.edition.clone(),
            build: os.build,
            ubr: os.ubr,
            builder_version: builder.into(),
            source_id: id.into(),
        };
        let mut records = Records::new();
        for key in keys {
            assert!(records.add_key(key));
        }
        let line = ok_line(source);
        let encoded = encode(&header, std::slice::from_ref(&line), &records).unwrap();
        LocalPartFile {
            source,
            header,
            line,
            counts: records.counts(),
            record_count: encoded.record_count,
            sha256: encoded.sha256,
            bytes: encoded.bytes,
            timings: Default::default(),
            threads: 1,
        }
    }

    fn part(source: LocalSource, id: &str, keys: &[&str]) -> LocalPartFile {
        part_of(&os(), source, id, keys, BUILDER_VERSION)
    }

    const ID_A: &str = "aaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbb";
    const ID_C: &str = "cccccccccccccccc";

    fn ids(s1: &str, s2: &str, s4: &str) -> PartIds {
        PartIds {
            s1: Some(s1.into()),
            s2: Some(s2.into()),
            s4: Some(s4.into()),
            ..PartIds::default()
        }
    }

    fn s3() -> (SourceLine, Records) {
        let mut records = Records::new();
        records.add_key(r"HKU\.DEFAULT\Software\S3Key");
        (ok_line(LocalSource::S3), records)
    }

    /// A cache with one part of each source, ids A.
    fn stored(dir: &Path) -> LocalCache {
        let c = cache(dir, true);
        c.store_part(
            &os(),
            &part(LocalSource::S1, ID_A, &[r"HKLM\SOFTWARE\S1Key"]),
        )
        .unwrap();
        c.store_part(
            &os(),
            &part(LocalSource::S2, ID_A, &[r"HKU\S-1-5-21-0-0-0-1000\S2Key"]),
        )
        .unwrap();
        c.store_part(
            &os(),
            &part(LocalSource::S4, ID_A, &[r"HKLM\SOFTWARE\Classes\S4Key"]),
        )
        .unwrap();
        c
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn states(loaded: &LoadedLocal) -> [PartState; 3] {
        [loaded.parts[0].1, loaded.parts[1].1, loaded.parts[2].1]
    }

    const HIT: PartState = PartState::Hit { derived: false };
    const DERIVED: PartState = PartState::Hit { derived: true };

    #[test]
    fn only_an_admin_only_directory_is_a_cache() {
        let dir = scratch("rule");
        // The source says a standard user can write it (a user-owned directory, an inherited Users
        // write ACE, a reparse point on the way: `purge_win::sid::is_admin_only_writable` answers
        // false for each, and its own tests say so).
        assert!(LocalCache::open(&dir, &fs_saying(&dir, false), true).is_none());
        assert!(LocalCache::open(&dir, &fs_saying(&dir, false), false).is_none());
        // The source does not know the directory (missing, unreadable).
        assert!(LocalCache::open(&dir, &Fixture::new(), true).is_none());
        // Only administrators can write it (a protected DACL).
        let c = LocalCache::open(&dir, &fs_saying(&dir, true), false).unwrap();
        assert_eq!(c.dir(), dir);
        assert!(!c.writable());
        // The live file system: a directory this test made in the user's temp is never accepted.
        let live = purge_source::live::LiveFileSystem::default();
        assert!(LocalCache::open(&dir, &live, true).is_none());
        // Opening never creates a directory.
        let missing = dir.join("none");
        assert!(LocalCache::open(&missing, &fs_saying(&missing, true), true).is_none());
        assert!(!missing.exists());
    }

    /// A junction where the cache directory should be is not a cache, even when the file system
    /// source vouches for the path and the junction leads to a directory that holds good parts.
    #[test]
    fn a_reparse_point_is_not_a_cache() {
        let dir = scratch("reparse");
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        stored(&real);
        let link = dir.join("baseline");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(made, "mklink /J failed");
        assert!(link.is_dir(), "the junction is followed by a plain look");
        for writable in [false, true] {
            assert!(LocalCache::open(&link, &fs_saying(&link, true), writable).is_none());
        }
        // The live file system refuses it as well (and its user-writable parents).
        let live = purge_source::live::LiveFileSystem::default();
        assert!(LocalCache::open(&link, &live, false).is_none());
        // Nothing behind the junction was touched.
        assert_eq!(names(&real).len(), 4);
        assert!(LocalCache::open(&real, &fs_saying(&real, true), false).is_some());
        fs::remove_dir(&link).unwrap();
    }

    /// The directory rule as the file system source states it (review BL-R1 "plant the cache"): a
    /// directory a standard user owns, one that inherits a write grant for Users from its parent,
    /// and one below a reparse point are refused with every good part in them; only a directory
    /// whose own protected DACL keeps everyone but administrators out is a cache. Nothing in a
    /// refused directory is read, repaired or removed.
    #[test]
    fn the_directory_rule_decides_and_nothing_else() {
        let base = scratch("acl");
        let (user_owned, inherited, below_link, protected) = (
            base.join("user-owned"),
            base.join("weak-parent").join("baseline"),
            base.join("link").join("baseline"),
            base.join("protected"),
        );
        for dir in [&user_owned, &inherited, &below_link, &protected] {
            fs::create_dir_all(dir).unwrap();
            stored(dir);
            // What a standard user would leave beside the parts.
            fs::write(dir.join("planted.tmp"), b"x").unwrap();
        }
        let path = |p: &Path| p.to_str().unwrap().to_owned();
        let source = Fixture::builder()
            // Owned by a standard user: the source answers for the directory itself.
            .dir(&path(&user_owned))
            .admin_only_writable(&path(&user_owned), false)
            // An inherited grant: the parent is writable, the directory says nothing of its own.
            .dir(&path(&inherited))
            .admin_only_writable(&path(inherited.parent().unwrap()), false)
            // A reparse point on the way: the source does not look behind it, so it has no answer.
            .reparse_dir(&path(below_link.parent().unwrap()), 0xA000_0003)
            // A protected DACL of its own: only this one is admin-only writable.
            .dir(&path(&protected))
            .admin_only_writable(&path(&protected), true)
            .build();
        assert_eq!(
            source.is_admin_only_writable(&path(&below_link)),
            Err(SourceError::ReparsePoint)
        );
        for refused in [&user_owned, &inherited, &below_link] {
            let before = names(refused);
            for writable in [false, true] {
                assert!(
                    LocalCache::open(refused, &source, writable).is_none(),
                    "{refused:?}"
                );
            }
            assert_eq!(names(refused), before, "{refused:?} was changed");
        }
        let c = LocalCache::open(&protected, &source, false).unwrap();
        let loaded = c.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        assert_eq!(states(&loaded), [DERIVED, HIT, HIT]);
    }

    #[test]
    fn parts_are_stored_and_put_together() {
        let dir = scratch("parts");
        let c = stored(&dir);
        assert_eq!(
            names(&dir),
            [
                "local-Professional-26100.9711-s1-aaaaaaaaaaaaaaaa.sets",
                "local-Professional-26100.9711-s1-aaaaaaaaaaaaaaaa.tsv.gz",
                "local-Professional-26100.9711-s2-aaaaaaaaaaaaaaaa.tsv.gz",
                "local-Professional-26100.9711-s4-aaaaaaaaaaaaaaaa.tsv.gz",
            ]
        );
        let loaded = c.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        assert!(loaded.notes.is_empty(), "{:?}", loaded.notes);
        assert_eq!(states(&loaded), [DERIVED, HIT, HIT]);
        assert!(loaded.missing().is_empty());
        let local = loaded.local.unwrap();
        assert!(local.complete(), "{:?}", local.incomplete_reasons());
        let order: Vec<LocalSource> = local.sources().iter().map(|l| l.source).collect();
        assert_eq!(order, LocalSource::REQUIRED);
        for key in [
            r"HKLM\SOFTWARE\S1Key",
            r"HKU\S-1-5-21-1-2-3-1001\S2Key",
            r"HKU\.DEFAULT\Software\S3Key",
            r"HKLM\SOFTWARE\Classes\S4Key",
        ] {
            assert!(local.has_key(key), "{key}");
        }
        assert!(!local.has_key(r"HKLM\SOFTWARE\Other"));
        let h = local.header();
        assert_eq!(
            h.source_id,
            PartIds::combined(Some(ID_A), Some(ID_A), Some(ID_A))
        );
        assert_eq!(
            (h.edition.as_str(), h.build, h.ubr),
            ("Professional", 26100, 9711)
        );
        assert!(c.has_part(&os(), LocalSource::S1, ID_A));
        assert!(!c.has_part(&os(), LocalSource::S1, ID_B));
    }

    #[test]
    fn a_change_of_one_source_misses_that_part_only() {
        let dir = scratch("invalidate");
        let c = stored(&dir);
        // An inbox package update: another S4 id. S1 and S2 stay (review BL-RM S7). The S4 part of
        // before answers presence until the new one is built (review BL-R1 S5); it is still what
        // the build has to make, and the local baseline is not complete with it.
        let loaded = c.load(&os(), &ids(ID_A, ID_A, ID_B), s3());
        assert_eq!(states(&loaded), [DERIVED, HIT, PartState::Stale]);
        assert_eq!(loaded.missing(), [LocalSource::S4]);
        let local = loaded.local.unwrap();
        assert!(local.has_key(r"HKLM\SOFTWARE\S1Key"));
        assert!(local.has_key(r"HKLM\SOFTWARE\Classes\S4Key"));
        assert!(!local.complete());
        assert_eq!(
            local.incomplete_reasons(),
            [
                "S4 incomplete: stale: the part with id aaaaaaaaaaaaaaaa of Professional-26100.9711 \
                 is used for presence only, this Windows now has id bbbbbbbbbbbbbbbb"
            ]
        );
        // Its id is neither the complete baseline's nor the one without S4.
        let stale = format!("stale:{ID_A}");
        assert_eq!(
            local.header().source_id,
            PartIds::combined(Some(ID_A), Some(ID_A), Some(&stale))
        );
        // A changed manifest directory stamp: another S1 id.
        let loaded = c.load(&os(), &ids(ID_B, ID_A, ID_A), s3());
        assert_eq!(states(&loaded), [PartState::Stale, HIT, HIT]);
        assert_eq!(loaded.missing(), [LocalSource::S1]);
        // A new revision: no part is this Windows' own; those of the revision before answer
        // presence.
        let newer = OsInfo { ubr: 9712, ..os() };
        let loaded = c.load(&newer, &ids(ID_A, ID_A, ID_A), s3());
        assert_eq!(states(&loaded), [PartState::Stale; 3]);
        assert_eq!(loaded.missing(), CACHED_PARTS);
        let local = loaded.local.unwrap();
        assert!(!local.complete());
        assert_eq!(local.header().ubr, 9712);
        assert!(local.has_key(r"HKLM\SOFTWARE\S1Key"));
        // Without an id (its source could not be stamped) there is no part of now either.
        let loaded = c.load(
            &os(),
            &PartIds {
                s1: None,
                ..ids(ID_A, ID_A, ID_A)
            },
            s3(),
        );
        assert_eq!(states(&loaded), [PartState::Stale, HIT, HIT]);
        assert!(
            loaded.local.unwrap().incomplete_reasons()[0]
                .ends_with("the id of this Windows as it is now is unknown")
        );
    }

    /// Review BL-R1 S5: after a servicing change the newest part of the same edition and build
    /// answers presence until the rebuild has ended. It never makes the local baseline complete, so
    /// a view over it has trust None, with or without a neighbour, and infers nothing.
    #[test]
    fn a_stale_part_answers_presence_and_never_gives_trust() {
        use crate::baseline_view::{Absence, BaselineTrust, BaselineView, fixture};

        let dir = scratch("stale");
        let c = stored(&dir);
        // A second S1 part (the build after an earlier change); the first is older.
        c.store_part(
            &os(),
            &part(LocalSource::S1, ID_B, &[r"HKLM\SOFTWARE\S1KeyB"]),
        )
        .unwrap();
        let old = dir.join(part_name("Professional-26100.9711", LocalSource::S1, ID_A));
        fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();

        // The manifests changed again: id C. The newest part, B, is taken; A is not.
        let now = ids(ID_C, ID_A, ID_A);
        let loaded = c.load(&os(), &now, s3());
        assert_eq!(states(&loaded), [PartState::Stale, HIT, HIT]);
        assert_eq!(loaded.missing(), [LocalSource::S1]);
        assert!(!c.has_part(&os(), LocalSource::S1, ID_C));
        assert_eq!(loaded.notes.len(), 1, "{:?}", loaded.notes);
        assert!(
            loaded.notes[0].contains("is used for presence only until the S1 part"),
            "{:?}",
            loaded.notes
        );
        let local = loaded.local.unwrap();
        assert!(local.has_key(r"HKLM\SOFTWARE\S1KeyB"));
        assert!(!local.has_key(r"HKLM\SOFTWARE\S1Key"));
        assert!(!local.complete());
        let s1 = &local.sources()[0];
        assert_eq!(
            (s1.source, s1.status),
            (LocalSource::S1, SourceStatus::Incomplete)
        );

        // The view: trust None, whatever the rules allow and whether or not there is a neighbour.
        let host = HostOs::new("Professional", 26100, 9711);
        let rules = fixture::open_rules();
        let neighbour = || {
            Neighbour::from_baseline(fixture::shipped(
                "Professional",
                26101,
                1,
                &[r"HKLM\SOFTWARE\NeighbourKey"],
            ))
        };
        for neighbours in [Vec::new(), vec![neighbour()]] {
            let view = BaselineView::assemble(&host, Some(local.clone()), neighbours, &rules);
            assert_eq!(view.trust(), BaselineTrust::None);
            assert!(view.has_key(r"HKLM\SOFTWARE\S1KeyB"));
            assert_eq!(
                view.key_absent(r"HKLM\SOFTWARE\Classes\CLSID\{NotThere}"),
                Absence::Unknown
            );
            assert_eq!(view.key_absent(r"HKLM\SOFTWARE\S1KeyB"), Absence::Present);
        }
        // The same parts, all current: complete, and the view may have trust.
        let current = c.load(&os(), &ids(ID_B, ID_A, ID_A), s3()).local.unwrap();
        assert!(current.complete());
        let view = BaselineView::assemble(&host, Some(current), vec![neighbour()], &rules);
        assert_eq!(view.trust(), BaselineTrust::Merged);

        // Never a part of another edition, another build or another builder version.
        let other = scratch("stale-other");
        let c = cache(&other, true);
        let edition = OsInfo {
            edition: "ProfessionalN".into(),
            ..os()
        };
        let build = OsInfo {
            build: 26200,
            ..os()
        };
        for foreign in [&edition, &build] {
            c.store_part(
                foreign,
                &part_of(
                    foreign,
                    LocalSource::S1,
                    ID_A,
                    &[r"HKLM\SOFTWARE\K"],
                    BUILDER_VERSION,
                ),
            )
            .unwrap();
        }
        let old_builder = part_of(&os(), LocalSource::S1, ID_A, &[r"HKLM\SOFTWARE\K"], "bl.0");
        fs::write(
            other.join(part_name("Professional-26100.9711", LocalSource::S1, ID_A)),
            &old_builder.bytes,
        )
        .unwrap();
        let loaded = c.load(&os(), &ids(ID_C, ID_C, ID_C), s3());
        assert_eq!(states(&loaded), [PartState::Missing; 3]);
        assert!(loaded.local.is_none());
    }

    #[test]
    fn ids_follow_their_own_stamp_and_the_builder_version() {
        let files = FileStamps {
            manifests: 10,
            manifest_bytes: 1000,
            manifest_newest_write: 5,
            hive_bytes: 256,
            hive_write: 7,
            problems: Vec::new(),
        };
        let packages = vec!["B_1".to_owned(), "a_1".to_owned()];
        let base = PartIds::from_stamps(&files, Some(&packages));
        let (s1, s2, s4) = (
            base.s1.clone().unwrap(),
            base.s2.clone().unwrap(),
            base.s4.clone().unwrap(),
        );
        assert!(plain_id(&s1) && plain_id(&s2) && plain_id(&s4));
        assert!(s1 != s2 && s2 != s4);
        // The manifest directory: count, size and newest write time, each alone.
        for changed in [
            FileStamps {
                manifests: 11,
                ..files.clone()
            },
            FileStamps {
                manifest_bytes: 1001,
                ..files.clone()
            },
            FileStamps {
                manifest_newest_write: 6,
                ..files.clone()
            },
        ] {
            let ids = PartIds::from_stamps(&changed, Some(&packages));
            assert_ne!(ids.s1, base.s1);
            assert_eq!((ids.s2, ids.s4), (base.s2.clone(), base.s4.clone()));
        }
        // The hive.
        let ids = PartIds::from_stamps(
            &FileStamps {
                hive_write: 8,
                ..files.clone()
            },
            Some(&packages),
        );
        assert_ne!(ids.s2, base.s2);
        assert_eq!((ids.s1, ids.s4), (base.s1.clone(), base.s4.clone()));
        // The package list: order and case do not matter, a new full name does.
        let same = vec!["A_1".to_owned(), "b_1".to_owned(), "b_1".to_owned()];
        assert_eq!(PartIds::from_stamps(&files, Some(&same)), base);
        let updated = vec!["B_2".to_owned(), "a_1".to_owned()];
        let ids = PartIds::from_stamps(&files, Some(&updated));
        assert_ne!(ids.s4, base.s4);
        assert_eq!((ids.s1, ids.s2), (base.s1.clone(), base.s2.clone()));
        // What could not be stamped has no id.
        let none = PartIds::from_stamps(&FileStamps::default(), None);
        assert_eq!((none.s1, none.s2, none.s4), (None, None, None));
        // The builder version is in every id.
        assert_eq!(s1, part_id(LocalSource::S1, "manifests\t10\t1000\t5\n"),);
        let mut sha = Sha256::new();
        sha.update(b"purge-local-part/1\nS1\nbl.0\nmanifests\t10\t1000\t5\n");
        assert_ne!(s1, hex(&sha.finalize()[..8]));
    }

    #[test]
    fn a_part_of_another_builder_source_or_id_is_a_miss() {
        let dir = scratch("mismatch");
        let c = cache(&dir, true);
        let name = part_name("Professional-26100.9711", LocalSource::S2, ID_A);
        // Another builder version under the right name.
        let other = part_of(&os(), LocalSource::S2, ID_A, &[r"HKLM\SOFTWARE\X"], "bl.0");
        assert!(c.store_part(&os(), &other).is_err());
        fs::write(dir.join(&name), &other.bytes).unwrap();
        let loaded = c.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        assert_eq!(states(&loaded), [PartState::Missing; 3]);
        assert!(
            loaded.notes[0].contains("written by builder"),
            "{:?}",
            loaded.notes
        );
        // The header carries another id than the name.
        fs::write(
            dir.join(&name),
            &part(LocalSource::S2, ID_B, &[r"HKLM\SOFTWARE\X"]).bytes,
        )
        .unwrap();
        let loaded = c.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        assert_eq!(states(&loaded), [PartState::Missing; 3]);
        assert!(
            loaded.notes[0].contains("is not the S2 part"),
            "{:?}",
            loaded.notes
        );
        // Another source's part under this source's name.
        fs::write(
            dir.join(&name),
            &part(LocalSource::S1, ID_A, &[r"HKLM\SOFTWARE\X"]).bytes,
        )
        .unwrap();
        assert!(!c.has_part(&os(), LocalSource::S2, ID_A));
        // Another Windows under this Windows' name.
        let newer = OsInfo { ubr: 1, ..os() };
        fs::write(
            dir.join(&name),
            &part_of(
                &newer,
                LocalSource::S2,
                ID_A,
                &[r"HKLM\SOFTWARE\X"],
                BUILDER_VERSION,
            )
            .bytes,
        )
        .unwrap();
        assert!(!c.has_part(&os(), LocalSource::S2, ID_A));
        // A truncated file (no #end).
        let good = part(LocalSource::S2, ID_A, &[r"HKLM\SOFTWARE\X"]).bytes;
        fs::write(dir.join(&name), &good[..good.len() - 12]).unwrap();
        assert!(!c.has_part(&os(), LocalSource::S2, ID_A));
        fs::write(dir.join(&name), &good).unwrap();
        assert!(c.has_part(&os(), LocalSource::S2, ID_A));
        // What is not a part is refused at the door.
        assert!(
            c.store_part(&os(), &part(LocalSource::S3, ID_A, &[]))
                .is_err()
        );
        assert!(
            c.store_part(&os(), &part(LocalSource::S1, "../../x", &[]))
                .is_err()
        );
        assert!(
            c.store_part(&newer, &part(LocalSource::S1, ID_A, &[]))
                .is_err()
        );
    }

    #[test]
    fn the_derived_form_is_never_trusted_alone() {
        let dir = scratch("derived");
        let c = stored(&dir);
        let text = dir.join(part_name("Professional-26100.9711", LocalSource::S1, ID_A));
        let sets = dir.join(sets_name(text.file_name().unwrap().to_str().unwrap()));
        let load = |c: &LocalCache| c.load(&os(), &ids(ID_A, ID_A, ID_A), s3());

        // A damaged derived file: the text is parsed, and a writable cache writes it again.
        let good = fs::read(&sets).unwrap();
        let mut bad = good.clone();
        let at = bad.len() - 40;
        bad[at] ^= 1;
        fs::write(&sets, &bad).unwrap();
        let loaded = load(&c);
        assert_eq!(states(&loaded)[0], HIT);
        assert!(loaded.local.unwrap().has_key(r"HKLM\SOFTWARE\S1Key"));
        assert_eq!(fs::read(&sets).unwrap(), good);
        assert_eq!(states(&load(&c))[0], DERIVED);

        // The text file changed under the derived one: the derived sets are not its, the text wins.
        let other = part(LocalSource::S1, ID_A, &[r"HKLM\SOFTWARE\Replaced"]);
        fs::write(&text, &other.bytes).unwrap();
        let reader = cache(&dir, false);
        let loaded = load(&reader);
        assert_eq!(states(&loaded)[0], HIT);
        let local = loaded.local.unwrap();
        assert!(local.has_key(r"HKLM\SOFTWARE\Replaced"));
        assert!(!local.has_key(r"HKLM\SOFTWARE\S1Key"));
        // A cache that is not writable left the stale derived file alone.
        assert_eq!(fs::read(&sets).unwrap(), good);

        // A derived file beside a truncated text file is no local baseline.
        fs::write(&text, &other.bytes[..other.bytes.len() - 9]).unwrap();
        let loaded = load(&reader);
        assert_eq!(states(&loaded)[0], PartState::Missing);
        assert!(
            loaded.notes[0].contains("is unusable"),
            "{:?}",
            loaded.notes
        );

        // A derived file without its text file is nothing.
        fs::remove_file(&text).unwrap();
        assert_eq!(states(&load(&reader))[0], PartState::Missing);
    }

    #[test]
    fn derived_sets_decode_only_what_was_encoded_for_these_bytes() {
        let sets = HashedSets {
            counts: RecordCounts {
                keys: 2,
                values: 1,
                dirs: 0,
                files: 1,
            },
            keys: vec![1, 5],
            values: vec![7],
            dirs: Vec::new(),
            files: vec![u64::MAX],
            leaves: vec![2, 3, 4],
            parts: vec![9],
        };
        let bound = [3u8; 32];
        let bytes = encode_sets(&bound, &sets);
        assert_eq!(decode_sets(&bytes, &bound), Some(sets.clone()));
        // Bound to other bytes.
        assert_eq!(decode_sets(&bytes, &[4u8; 32]), None);
        // Truncated, extended, or any byte changed.
        assert_eq!(decode_sets(&bytes[..bytes.len() - 1], &bound), None);
        assert_eq!(decode_sets(&[&bytes[..], &[0]].concat(), &bound), None);
        assert_eq!(decode_sets(&[], &bound), None);
        for at in [0, 13, 20, bytes.len() - 33, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[at] ^= 0x10;
            assert_eq!(decode_sets(&bad, &bound), None, "byte {at}");
        }
        // Resealed with its own hash, the content is still judged: another scheme, sets out of
        // order, a length that runs past the end.
        let reseal = |mut body: Vec<u8>| {
            let sha = Sha256::digest(&body);
            body.extend_from_slice(&sha);
            body
        };
        let body = &bytes[..bytes.len() - 32];
        assert_eq!(
            decode_sets(&reseal(body.to_vec()), &bound),
            Some(sets.clone())
        );
        let mut scheme = body.to_vec();
        scheme[SETS_MAGIC.len() + 4] ^= 1;
        assert_eq!(decode_sets(&reseal(scheme), &bound), None);
        let unordered = HashedSets {
            keys: vec![5, 1],
            ..sets.clone()
        };
        let b = encode_sets(&bound, &unordered);
        assert_eq!(decode_sets(&b, &bound), None);
        let mut long = body.to_vec();
        let first_len = SETS_MAGIC.len() + 4 + HashedSets::scheme().len() + 32 + 32;
        long[first_len..first_len + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode_sets(&reseal(long), &bound), None);
    }

    #[test]
    fn two_files_of_a_source_are_kept() {
        let dir = scratch("keep");
        let c = cache(&dir, true);
        let age = |name: &str, secs: u64| {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(dir.join(name))
                .unwrap();
            file.set_modified(SystemTime::now() - Duration::from_secs(secs))
                .unwrap();
        };
        for (id, secs) in [(ID_A, 300), (ID_B, 200)] {
            c.store_part(&os(), &part(LocalSource::S1, id, &[r"HKLM\SOFTWARE\K"]))
                .unwrap();
            age(
                &part_name("Professional-26100.9711", LocalSource::S1, id),
                secs,
            );
        }
        c.store_part(&os(), &part(LocalSource::S4, ID_A, &[r"HKLM\SOFTWARE\K"]))
            .unwrap();
        // A part of another Windows counts as one of the two.
        let newer = OsInfo { ubr: 9712, ..os() };
        c.store_part(
            &newer,
            &part_of(
                &newer,
                LocalSource::S1,
                ID_C,
                &[r"HKLM\SOFTWARE\K"],
                BUILDER_VERSION,
            ),
        )
        .unwrap();
        assert_eq!(
            names(&dir),
            [
                "local-Professional-26100.9711-s1-bbbbbbbbbbbbbbbb.sets",
                "local-Professional-26100.9711-s1-bbbbbbbbbbbbbbbb.tsv.gz",
                "local-Professional-26100.9711-s4-aaaaaaaaaaaaaaaa.tsv.gz",
                "local-Professional-26100.9712-s1-cccccccccccccccc.sets",
                "local-Professional-26100.9712-s1-cccccccccccccccc.tsv.gz",
            ],
            "the oldest S1 part and its derived file are gone; S4 is untouched"
        );
        // Storing the same part again replaces it and removes nothing.
        c.store_part(&os(), &part(LocalSource::S1, ID_B, &[r"HKLM\SOFTWARE\K2"]))
            .unwrap();
        assert_eq!(names(&dir).len(), 5);
        assert!(c.has_part(&os(), LocalSource::S1, ID_B));
        let loaded = c.load(&os(), &ids(ID_B, ID_A, ID_A), s3());
        assert!(loaded.local.unwrap().has_key(r"HKLM\SOFTWARE\K2"));
    }

    #[test]
    fn a_temporary_file_left_behind_is_ignored_and_removed() {
        let dir = scratch("temp");
        let old = dir.join("local-Professional-26100.9711-s1-aaaaaaaaaaaaaaaa.tsv.gz.1.0.tmp");
        let fresh = dir.join("local-Professional-26100.9711-s2-aaaaaaaaaaaaaaaa.tsv.gz.2.0.tmp");
        let bytes = part(LocalSource::S1, ID_A, &[r"HKLM\SOFTWARE\K"]).bytes;
        fs::write(&old, &bytes).unwrap();
        fs::write(&fresh, &bytes).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        // An engine that is not elevated ignores both and removes nothing.
        let reader = cache(&dir, false);
        let loaded = reader.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        assert!(loaded.local.is_none());
        assert!(loaded.notes.is_empty(), "{:?}", loaded.notes);
        assert!(old.exists() && fresh.exists());
        // An elevated one removes the one a dead writer left; a file that may still be written stays.
        let c = cache(&dir, true);
        assert!(!old.exists());
        assert!(fresh.exists());
        assert!(c.load(&os(), &ids(ID_A, ID_A, ID_A), s3()).local.is_none());
        // A store leaves no temporary file of its own.
        c.store_part(&os(), &part(LocalSource::S1, ID_A, &[r"HKLM\SOFTWARE\K"]))
            .unwrap();
        assert_eq!(
            names(&dir).iter().filter(|n| n.ends_with(".tmp")).count(),
            1
        );
    }

    #[test]
    fn an_engine_that_is_not_elevated_never_writes() {
        let dir = scratch("readonly");
        let writer = stored(&dir);
        let sets = dir.join("local-Professional-26100.9711-s1-aaaaaaaaaaaaaaaa.sets");
        fs::remove_file(&sets).unwrap();
        let before = names(&dir);
        let reader = cache(&dir, false);
        let err = reader
            .store_part(&os(), &part(LocalSource::S1, ID_B, &[r"HKLM\SOFTWARE\K"]))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let loaded = reader.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        assert_eq!(states(&loaded), [HIT, HIT, HIT]);
        assert_eq!(names(&dir), before, "a read-only cache wrote something");
        // The elevated engine writes the derived form at its next load.
        assert_eq!(
            states(&writer.load(&os(), &ids(ID_A, ID_A, ID_A), s3()))[0],
            HIT
        );
        assert!(sets.exists());
    }

    #[test]
    fn without_elevation_the_newest_s4_part_is_used_unchecked() {
        let dir = scratch("unverified");
        let c = stored(&dir);
        let unknown = PartIds {
            s4: None,
            s4_unverified: true,
            ..ids(ID_A, ID_A, ID_A)
        };
        let loaded = c.load(&os(), &unknown, s3());
        assert_eq!(states(&loaded), [DERIVED, HIT, PartState::Unverified]);
        assert!(loaded.missing().is_empty());
        let local = loaded.local.unwrap();
        assert!(local.has_key(r"HKLM\SOFTWARE\Classes\S4Key"));
        assert!(!local.complete());
        assert_eq!(
            local.incomplete_reasons(),
            [
                "S4 incomplete: not checked against the installed packages (the engine is not elevated)"
            ]
        );
        // The part of another revision is not this Windows' own: stale, and still to be built.
        let newer = OsInfo { ubr: 9712, ..os() };
        let loaded = c.load(&newer, &unknown, s3());
        assert_eq!(states(&loaded)[2], PartState::Stale);
        assert!(loaded.missing().contains(&LocalSource::S4));
        // Unknown without that reason (an elevated engine that could not list the packages): the
        // newest part answers presence, and S4 is still to be built.
        let failed = PartIds {
            s4: None,
            ..ids(ID_A, ID_A, ID_A)
        };
        let loaded = c.load(&os(), &failed, s3());
        assert_eq!(states(&loaded)[2], PartState::Stale);
        assert_eq!(loaded.missing(), [LocalSource::S4]);
        assert!(!loaded.local.unwrap().complete());
    }

    #[test]
    fn an_s3_that_could_not_be_read_whole_keeps_the_local_baseline_incomplete() {
        let dir = scratch("s3");
        let c = stored(&dir);
        let (mut line, records) = s3();
        line.status = SourceStatus::Incomplete;
        line.reasons
            .push("7 keys not read whole (unreadable)".into());
        let local = c
            .load(&os(), &ids(ID_A, ID_A, ID_A), (line, records))
            .local
            .unwrap();
        assert!(!local.complete());
        // Presence is still answered from everything.
        assert!(local.has_key(r"HKU\.DEFAULT\Software\S3Key"));
        assert!(local.has_key(r"HKLM\SOFTWARE\S1Key"));
    }

    /// The parts of the fixture machine, built and stored, give the hashed sets of the one-file
    /// build of the same machine; S3 comes from the registry at load.
    #[test]
    fn built_parts_equal_the_whole_build() {
        let dir = scratch("built");
        let f = with_hive(machine().build());
        let opts = options(&f);
        let whole = build(&f, &os(), &opts).unwrap();
        let whole = LocalBaseline::from_bytes(&whole.bytes).unwrap();
        assert!(whole.complete());

        let ids = PartIds::read(&f, &f, &f);
        assert!(ids.problems.is_empty(), "{:?}", ids.problems);
        assert!(!ids.s4_unverified);
        assert_eq!(
            ids,
            PartIds::from_stamps(&opts.stamps, Some(&[SHELL.to_owned()]))
        );
        assert_eq!(inbox_package_names(&f, &f).unwrap(), [SHELL]);

        let c = cache(&dir, true);
        let control = BuildControl::new();
        for source in CACHED_PARTS {
            let id = ids.get(source).unwrap();
            let part = build_part(&f, &os(), &opts, source, id, &control).unwrap();
            assert_eq!(part.line.status, SourceStatus::Ok, "{:?}", part.line);
            assert_eq!(part.header.source_id, id);
            c.store_part(&os(), &part).unwrap();
        }
        assert!(build_part(&f, &os(), &opts, LocalSource::S3, ID_A, &control).is_err());
        let loaded = c.load(&os(), &ids, read_live_s3(&f));
        assert_eq!(states(&loaded), [DERIVED, HIT, HIT]);
        let local = loaded.local.unwrap();
        assert!(local.complete(), "{:?}", local.incomplete_reasons());
        assert!(local.has_key(r"HKU\S-1-5-18\Software\Microsoft\PurgeTest"));
        let s3_line = &local.sources()[2];
        assert_eq!(
            (s3_line.source, s3_line.fact("keys")),
            (LocalSource::S3, Some("6"))
        );
        let (a, b) = (whole.into_hashed_sets(), local.into_hashed_sets());
        assert_eq!(a.keys, b.keys);
        assert_eq!(a.values, b.values);
        assert_eq!(a.dirs, b.dirs);
        assert_eq!(a.files, b.files);
        assert_eq!(a.leaves, b.leaves);
        assert_eq!(a.parts, b.parts);

        // Not elevated: the package list is the account's own, so S4 has no id.
        let unelevated = with_hive(machine().elevated(false).build());
        let ids = PartIds::read(&unelevated, &unelevated, &unelevated);
        assert!(ids.s4.is_none() && ids.s4_unverified);
        assert!(ids.s1.is_some() && ids.s2.is_some());

        // An updated inbox package: only the S4 id moves.
        let updated = with_hive(
            machine()
                .package(PackageInfo {
                    full_name: "Microsoft.Windows.Other_10.0.2.0_neutral_neutral_cw5n1h2txyewy"
                        .into(),
                    family: "Microsoft.Windows.Other_cw5n1h2txyewy".into(),
                    install_location: None,
                    external_location: None,
                    sparse: false,
                    users: Vec::new(),
                    is_framework: false,
                    is_resource: false,
                    signature_kind: PackageSignatureKind::System,
                })
                .build(),
        );
        let after = PartIds::read(&updated, &updated, &updated);
        assert_ne!(after.s4, ids_of(&f).s4);
        assert_eq!((after.s1, after.s2), (ids_of(&f).s1, ids_of(&f).s2));
    }

    fn ids_of(f: &Fixture) -> PartIds {
        PartIds::read(f, f, f)
    }

    fn shipped(dir: &Path, name: &str, header: &str, key: &str) -> NeighbourFile {
        let path = dir.join(format!("{name}.tsv.gz"));
        fs::write(
            &path,
            format!("#purge-baseline 1\tT\tPC\t{header}\nK\t{key}\n"),
        )
        .unwrap();
        let (edition, version) = name.rsplit_once('-').unwrap();
        let (build, ubr) = version.split_once('.').unwrap();
        NeighbourFile {
            path,
            edition: edition.into(),
            build: build.parse().unwrap(),
            ubr: ubr.parse().unwrap(),
        }
    }

    #[test]
    fn neighbours_load_through_their_derived_form() {
        let kb = scratch("kb");
        let dir = scratch("nb");
        let host = HostOs::new("Professional", 26100, 9711);
        let rule = NeighbourRule::default();
        shipped(
            &kb,
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\near",
        );
        shipped(
            &kb,
            "Enterprise-26200.5",
            "Enterprise\t26200.5",
            r"hklm\\software\\far",
        );
        // Header and name disagree: never a neighbour, never a derived file.
        shipped(
            &kb,
            "Professional-26100.2",
            "Professional\t26100.3",
            r"hklm\\software\\liar",
        );

        let keys = |n: &[Neighbour]| -> Vec<(String, Vec<u64>)> {
            n.iter()
                .map(|n| (n.name(), n.clone().into_hashed_sets().keys))
                .collect()
        };
        let mut plain_warnings = Vec::new();
        let plain = load_neighbours(None, &kb, &host, rule, &mut plain_warnings);
        assert_eq!(plain.len(), 2);
        assert_eq!(plain_warnings.len(), 1, "{plain_warnings:?}");
        assert!(names(&dir).is_empty());

        // Not elevated: read from the text, nothing written.
        let reader = cache(&dir, false);
        let mut w = Vec::new();
        assert_eq!(
            keys(&load_neighbours(Some(&reader), &kb, &host, rule, &mut w)),
            keys(&plain)
        );
        assert!(names(&dir).is_empty());

        // Elevated: the derived forms are written, and the next load reads them.
        let c = cache(&dir, true);
        let mut w = Vec::new();
        let first = load_neighbours(Some(&c), &kb, &host, rule, &mut w);
        assert_eq!(keys(&first), keys(&plain));
        assert_eq!(w, plain_warnings);
        assert_eq!(
            names(&dir),
            [
                "shipped-Enterprise-26200.5.sets",
                "shipped-Professional-26100.1.sets"
            ]
        );
        let near = NeighbourFile {
            path: kb.join("Professional-26100.1.tsv.gz"),
            edition: "Professional".into(),
            build: 26100,
            ubr: 1,
        };
        let sha: [u8; 32] = Sha256::digest(fs::read(&near.path).unwrap()).into();
        assert!(
            reader
                .read_sets("shipped-Professional-26100.1.sets", &sha)
                .is_some()
        );
        assert_eq!(
            keys(&load_neighbours(
                Some(&reader),
                &kb,
                &host,
                rule,
                &mut Vec::new()
            )),
            keys(&plain)
        );

        // The shipped file changed: its derived form is not its any more, the file is parsed.
        shipped(
            &kb,
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\changed",
        );
        let again = load_neighbours(Some(&reader), &kb, &host, rule, &mut Vec::new());
        let fresh = load_neighbours(None, &kb, &host, rule, &mut Vec::new());
        assert_eq!(keys(&again), keys(&fresh));
        assert_ne!(keys(&again), keys(&plain));

        // A shipped file that is gone takes its derived form with it at the next elevated load.
        fs::remove_file(kb.join("Enterprise-26200.5.tsv.gz")).unwrap();
        load_neighbours(Some(&c), &kb, &host, rule, &mut Vec::new());
        assert_eq!(names(&dir), ["shipped-Professional-26100.1.sets"]);
    }

    #[test]
    fn live_s3_reads_the_registry_source() {
        let f = Fixture::builder()
            .sz(r"HKU\.DEFAULT\Software\Vendor", "v", "1")
            .build();
        let (line, records) = read_live_s3(&f);
        assert_eq!(line.source, LocalSource::S3);
        assert_eq!(line.status, SourceStatus::Ok);
        assert!(records.contains_key(r"HKU\.DEFAULT\Software\Vendor"));
        assert!(records.contains_value(r"HKU\.DEFAULT\Software\Vendor", "v"));
        // No such key: a failed line, no records.
        let (line, records) = read_live_s3(&Fixture::new());
        assert_eq!(line.status, SourceStatus::Failed);
        assert!(records.is_empty());
    }

    /// With a file rule, a part file that fails it is not read: a miss with a note, never an error,
    /// and the other parts still load. A missing file stays a plain miss.
    #[test]
    fn a_file_that_fails_the_rule_is_a_miss() {
        let dir = scratch("file-rule");
        stored(&dir);
        let rule: FileRule = std::sync::Arc::new(|p: &Path| !p.to_string_lossy().contains("-s1-"));
        let c =
            LocalCache::open_with_rule(&dir, &fs_saying(&dir, true), false, Some(rule)).unwrap();
        let loaded = c.load(&os(), &ids(ID_A, ID_A, ID_A), s3());
        let s = states(&loaded);
        assert!(!matches!(s[0], PartState::Hit { .. }), "{s:?}");
        assert!(matches!(s[1], PartState::Hit { .. }), "{s:?}");
        assert!(matches!(s[2], PartState::Hit { .. }), "{s:?}");
        assert!(
            loaded.notes.iter().any(|n| n.contains("cannot be read")),
            "{:?}",
            loaded.notes
        );
        let missing = c.load(&os(), &ids(ID_B, ID_A, ID_A), s3());
        assert!(
            !missing
                .notes
                .iter()
                .any(|n| n.contains(&format!("{ID_B}.tsv.gz cannot be read"))),
            "{:?}",
            missing.notes
        );
        // The live rule: a file in a temp directory a standard user can write fails it.
        let part = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().ends_with(".tsv.gz"))
            .unwrap();
        assert!(!admin_only_file(&part));
        let _ = fs::remove_dir_all(&dir);
    }

    /// Files held in memory, for [`LocalCache::with_files`]: nothing on disk exists.
    #[derive(Debug, Default)]
    struct MemFiles(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

    impl MemFiles {
        fn names(&self) -> Vec<String> {
            self.0.lock().unwrap().keys().cloned().collect()
        }
    }

    impl CacheFiles for MemFiles {
        fn list(&self) -> Vec<(String, SystemTime)> {
            self.0
                .lock()
                .unwrap()
                .keys()
                .map(|name| (name.clone(), SystemTime::now()))
                .collect()
        }
        fn read(&self, name: &str, max: u64) -> io::Result<Vec<u8>> {
            let files = self.0.lock().unwrap();
            let bytes = files.get(name).ok_or(io::ErrorKind::NotFound)?;
            if bytes.len() as u64 > max {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(bytes.clone())
        }
        fn replace(&self, name: &str, temp: &str, bytes: &[u8]) -> io::Result<()> {
            assert!(temp.starts_with(&format!("{name}.")) && temp.ends_with(TEMP_SUFFIX));
            self.0
                .lock()
                .unwrap()
                .insert(name.to_owned(), bytes.to_vec());
            Ok(())
        }
        fn remove(&self, name: &str) -> io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(name)
                .map(drop)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    /// The broker's cache reaches its directory only through [`CacheFiles`] (its store's checked
    /// `baseline` handle): with files held in memory and a directory that does not exist, it stores,
    /// derives, loads and prunes exactly as the cache by path does, under the same names.
    #[test]
    fn a_cache_with_its_own_files_never_touches_the_directory_by_path() {
        let nowhere =
            std::env::temp_dir().join(format!("purge-local-cache-{}-nowhere", std::process::id()));
        let _ = fs::remove_dir_all(&nowhere);
        let files = std::sync::Arc::new(MemFiles::default());
        let mem = LocalCache::with_files(&nowhere, files.clone(), true);
        let dir = scratch("with-files");
        let by_path = cache(&dir, true);
        for c in [&mem, &by_path] {
            for (source, key) in [
                (LocalSource::S1, r"HKLM\SOFTWARE\S1Key"),
                (LocalSource::S2, r"HKU\S-1-5-21-0-0-0-1000\S2Key"),
                (LocalSource::S4, r"HKLM\SOFTWARE\S4Key"),
            ] {
                for id in [ID_A, ID_B, ID_C] {
                    c.store_part(&os(), &part(source, id, &[key])).unwrap();
                }
            }
        }
        assert_eq!(files.names(), names(&dir));
        let a = mem.load(&os(), &ids(ID_C, ID_C, ID_C), s3());
        let b = by_path.load(&os(), &ids(ID_C, ID_C, ID_C), s3());
        assert_eq!(states(&a), states(&b));
        assert!(
            states(&a)
                .iter()
                .all(|s| matches!(s, PartState::Hit { .. })),
            "{:?}",
            states(&a)
        );
        assert_eq!(
            a.local.as_ref().unwrap().header().source_id,
            b.local.as_ref().unwrap().header().source_id
        );
        assert!(!nowhere.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
