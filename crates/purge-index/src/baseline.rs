//! The clean-Windows baseline: what a fresh install of one (edition, build.ubr) contains
//! (ENGINE_PLAN.md §5.5, §5.3 `WindowsBaseline` / `ProvenOwnedSkeleton`, §5.7.1 step 3).
//!
//! A baseline is a `kb/baselines/<EditionID>-<build>.<ubr>.tsv.gz` file written by `rigtool baseline`
//! (format: `kb/baselines/README.md`, `vm/RIG.md` §8): a `#purge-baseline 1` header, a `#source` line and
//! then `K` (key), `V` (key, name, type, hash), `D` (directory) and `F` (file) records.
//!
//! # Selection
//!
//! [`Baseline::select`] returns a baseline only for an **exact** (edition, build, ubr) match, both in the
//! file name and in the file's own header. Anything else is `None`, and the caller then works values-only
//! (§5.7.1 step 3): a baseline of a neighbouring build must never vouch that a key is not Windows' own.
//!
//! # Representation
//!
//! Only membership is ever asked, so the loader keeps 64-bit FNV-1a hashes of the normalised names in
//! sorted vectors and drops the text: about 20 MB for the 310k-key Professional file instead of the
//! 117 MB of text. A hash collision can only make an item look *present* in the baseline, which is the
//! safe direction (it blocks a deletion, never allows one).
//!
//! # Normalisation (applied to the file at load and to every query)
//!
//! - Case: Unicode lower-casing, the same fold as [`purge_guard::prefix::fold`].
//! - Roots: `HKEY_LOCAL_MACHINE` / `HKEY_USERS` are read as `HKLM` / `HKU`. Callers should pass physical
//!   locations, but an unbound view still fails closed: `HKCU` is read as the baseline user's hive and
//!   `HKCR` as "the machine classes or the user's classes", so a key Windows ships is never reported
//!   absent only because of its spelling.
//! - Registry views: `HKLM\SOFTWARE\WOW6432Node\Classes` is a link to `HKLM\SOFTWARE\Classes\WOW6432Node`
//!   (the snapshot does not follow links) and is folded onto it. Because most keys of the 32-bit view
//!   are shared with the 64-bit one rather than stored twice, a query for a 32-bit spelling
//!   (`HKLM\SOFTWARE\WOW6432Node\X`, `…\Classes\WOW6432Node\X`) also matches when the baseline has the
//!   64-bit twin `X`. This only ever makes more things count as Windows' own.
//! - Control sets: `HKLM\SYSTEM\ControlSet00N` and `HKLM\SYSTEM\CurrentControlSet` are the same key.
//! - Users: every key segment that is a user SID (`S-1-5-21-…`, `S-1-12-1-…`, with or without the
//!   `_Classes` suffix) becomes [`SID_PLACEHOLDER`], so the baseline machine's user stands for any user of
//!   any machine. `HKU\<SID>\Software\Classes` is folded onto `HKU\<SID>_Classes`, and `HKU\S-1-5-18` onto
//!   `HKU\.DEFAULT`.
//! - Paths: a `\\?\` prefix and trailing separators are dropped, `/` is read as `\`, and the profile
//!   directory `X:\Users\<name>` (other than `Default`, `Default User`, `Public`, `All Users`) becomes
//!   [`USER_PLACEHOLDER`]. A profile stored elsewhere is handled by [`Baseline::has_profile_path`].
//!
//! Value names are folded but otherwise taken literally; the default value's name is the empty string.
//!
//! # Scope
//!
//! A baseline only knows what the rig captured (`vm/RIG.md` §2): `HKLM\SOFTWARE`,
//! `HKLM\SYSTEM\CurrentControlSet` (without `Enum` and `Control\DeviceClasses`), the loaded user hives,
//! and a fixed list of directories, some of them one level deep only. "Not in the baseline" means "not
//! Windows' own" **only inside that scope**; [`Baseline::key_in_scope`] and [`Baseline::path_in_scope`]
//! say whether a negative answer carries any weight.

use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use purge_guard::prefix;

/// What a user SID is replaced by in normalised keys.
pub const SID_PLACEHOLDER: &str = "<sid>";

/// What the profile directory name is replaced by in normalised paths.
pub const USER_PLACEHOLDER: &str = "<user>";

/// The only header version this loader reads.
pub const FORMAT_VERSION: u32 = 1;

const HEADER_TAG: &str = "#purge-baseline";
const SOURCE_TAG: &str = "#source";

/// Why a baseline could not be loaded.
#[derive(Debug)]
pub enum BaselineError {
    /// The file could not be read or decompressed.
    Io(io::Error),
    /// The first line is not a `#purge-baseline` header with five fields.
    BadHeader(String),
    /// The header names a format version other than [`FORMAT_VERSION`].
    UnsupportedVersion(String),
    /// A record line could not be parsed.
    BadRecord {
        /// 1-based line number.
        line: u64,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The file's header does not describe the (edition, build.ubr) its name promises.
    HeaderMismatch {
        /// What the file name says.
        expected: String,
        /// What the header says.
        found: String,
    },
}

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the baseline: {e}"),
            Self::BadHeader(h) => write!(f, "not a baseline header: {h:?}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "baseline format version {v:?} is not supported")
            }
            Self::BadRecord { line, reason } => write!(f, "baseline line {line}: {reason}"),
            Self::HeaderMismatch { expected, found } => {
                write!(
                    f,
                    "baseline header says {found}, the file name says {expected}"
                )
            }
        }
    }
}

impl std::error::Error for BaselineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BaselineError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// How many records of each type the file holds, as written (before normalisation merges any).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordCounts {
    /// `K` records.
    pub keys: u64,
    /// `V` records.
    pub values: u64,
    /// `D` records.
    pub dirs: u64,
    /// `F` records.
    pub files: u64,
}

/// What the baseline records about one registry value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineValue {
    /// The registry value type (`REG_SZ` = 1 …).
    pub ty: u32,
    /// The first 8 bytes of the SHA-256 of the data, i.e. the record's 16 hex digits read as a
    /// big-endian number (the same hash `vm/RIG.md` snapshots and subtree captures use).
    pub data_hash: u64,
}

impl BaselineValue {
    /// The hash as the 16 lower-case hex digits found in snapshots.
    pub fn hash_hex(&self) -> String {
        format!("{:016x}", self.data_hash)
    }
}

/// Whether a baseline path is a directory or a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// A `D` record.
    Dir,
    /// An `F` record.
    File,
}

#[derive(Debug, Clone, Copy)]
struct ValueRec {
    id: u64,
    ty: u32,
    data_hash: u64,
}

/// The contents of clean Windows for one (edition, build.ubr). See the module documentation.
#[derive(Debug, Clone)]
pub struct Baseline {
    edition: String,
    build: u32,
    ubr: u32,
    captured_at: String,
    computer: String,
    source: String,
    counts: RecordCounts,
    keys: Vec<u64>,
    values: Vec<ValueRec>,
    dirs: Vec<u64>,
    files: Vec<u64>,
    leaves: Vec<u64>,
    /// Delimited parts of the leaves that are not the whole leaf (see [`Baseline::has_token`]).
    parts: Vec<u64>,
}

impl Baseline {
    /// The file name a baseline of this (edition, build, ubr) has: `<EditionID>-<build>.<ubr>.tsv.gz`.
    pub fn file_name(edition: &str, build: u32, ubr: u32) -> String {
        format!("{edition}-{build}.{ubr}.tsv.gz")
    }

    /// The baseline in `dir` for exactly this (edition, build, ubr), or `None`.
    ///
    /// `None` also covers a file that cannot be read or whose header disagrees with its name; use
    /// [`Baseline::try_select`] to tell those apart from "no such baseline". With `None` the caller goes
    /// values-only (§5.7.1 step 3).
    pub fn select(dir: &Path, edition: &str, build: u32, ubr: u32) -> Option<Baseline> {
        Self::try_select(dir, edition, build, ubr).ok().flatten()
    }

    /// Like [`Baseline::select`], but reports a baseline file that exists and is unusable.
    pub fn try_select(
        dir: &Path,
        edition: &str,
        build: u32,
        ubr: u32,
    ) -> Result<Option<Baseline>, BaselineError> {
        let plain = !edition.is_empty()
            && edition
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !plain {
            return Ok(None);
        }
        let path: PathBuf = dir.join(Self::file_name(edition, build, ubr));
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let baseline = Self::from_bytes(&bytes)?;
        if !baseline.is_for(edition, build, ubr) {
            return Err(BaselineError::HeaderMismatch {
                expected: format!("{edition} {build}.{ubr}"),
                found: format!("{} {}.{}", baseline.edition, baseline.build, baseline.ubr),
            });
        }
        Ok(Some(baseline))
    }

    /// Loads a baseline file, whatever its name.
    pub fn load(path: &Path) -> Result<Baseline, BaselineError> {
        Self::from_bytes(&fs::read(path)?)
    }

    /// Parses a baseline from memory: gzip (recognised by its magic number) or the plain text.
    pub fn from_bytes(bytes: &[u8]) -> Result<Baseline, BaselineError> {
        if bytes.starts_with(&[0x1f, 0x8b]) {
            let gz = flate2::bufread::MultiGzDecoder::new(bytes);
            Self::from_reader(BufReader::with_capacity(1 << 18, gz))
        } else {
            Self::from_reader(bytes)
        }
    }

    /// Parses the plain (already decompressed) text of a baseline.
    pub fn from_reader<R: BufRead>(mut reader: R) -> Result<Baseline, BaselineError> {
        let mut line: Vec<u8> = Vec::with_capacity(512);
        let mut line_no: u64 = 1;
        if !read_line(&mut reader, &mut line)? {
            return Err(BaselineError::BadHeader(String::new()));
        }
        let mut out = parse_header(&line)?;
        let mut records = RecordParser::new();
        while read_line(&mut reader, &mut line)? {
            line_no += 1;
            if line.is_empty() {
                continue;
            }
            if line[0] == b'#' {
                if let Some(rest) = line.strip_prefix(SOURCE_TAG.as_bytes()) {
                    out.source = String::from_utf8_lossy(rest).trim().to_owned();
                }
                continue;
            }
            records.add(&mut out, &line, line_no)?;
        }
        out.finish_sets();
        Ok(out)
    }

    /// A baseline with no records yet, for a reader of another header (the local baseline,
    /// [`crate::local_baseline::LocalBaseline`]) that feeds a [`RecordParser`] and then calls
    /// [`Baseline::finish_sets`].
    pub(crate) fn empty(
        edition: &str,
        build: u32,
        ubr: u32,
        captured_at: &str,
        computer: &str,
        source: &str,
    ) -> Baseline {
        Baseline {
            edition: edition.to_owned(),
            build,
            ubr,
            captured_at: captured_at.to_owned(),
            computer: computer.to_owned(),
            source: source.to_owned(),
            counts: RecordCounts::default(),
            keys: Vec::new(),
            values: Vec::new(),
            dirs: Vec::new(),
            files: Vec::new(),
            leaves: Vec::new(),
            parts: Vec::new(),
        }
    }

    /// Sorts and de-duplicates the hashed sets once every record is in.
    pub(crate) fn finish_sets(&mut self) {
        for set in [
            &mut self.keys,
            &mut self.dirs,
            &mut self.files,
            &mut self.leaves,
            &mut self.parts,
        ] {
            set.sort_unstable();
            set.dedup();
            set.shrink_to_fit();
        }
        // Stable, so that of two records normalising to the same value the first one in the file wins.
        self.values.sort_by_key(|v| v.id);
        self.values.dedup_by_key(|v| v.id);
        self.values.shrink_to_fit();
    }

    /// The Windows `EditionID` the baseline was taken on (e.g. `Professional`).
    pub fn edition(&self) -> &str {
        &self.edition
    }

    /// The build number (e.g. 26100).
    pub fn build(&self) -> u32 {
        self.build
    }

    /// The update build revision (e.g. 1742).
    pub fn ubr(&self) -> u32 {
        self.ubr
    }

    /// When the baseline was written, as the header's ISO-8601 text.
    pub fn captured_at(&self) -> &str {
        &self.captured_at
    }

    /// The machine it was taken on.
    pub fn computer(&self) -> &str {
        &self.computer
    }

    /// The snapshot it was built from (the `#source` line); empty when the file has none.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The number of records of each type in the file.
    pub fn counts(&self) -> RecordCounts {
        self.counts
    }

    /// Whether this baseline describes exactly this Windows. The edition compares case-insensitively.
    pub fn is_for(&self, edition: &str, build: u32, ubr: u32) -> bool {
        self.edition.eq_ignore_ascii_case(edition) && self.build == build && self.ubr == ubr
    }

    /// Whether clean Windows has this registry key.
    pub fn has_key(&self, key: &str) -> bool {
        key_forms(key)
            .iter()
            .any(|form| self.keys.binary_search(&hash(form.as_bytes())).is_ok())
    }

    /// [`Baseline::has_key`] without the 64-bit twin, for the one place where the two registry views
    /// hold genuinely separate keys: `HKLM\SOFTWARE\WOW6432Node\<x>[\…]` with `<x>` outside
    /// `SHARED_SOFTWARE_KEYS`. There `HKLM\SOFTWARE\<x>` and `HKLM\SOFTWARE\WOW6432Node\<x>` are two
    /// keys (the snapshot walks the 64-bit view and records the 32-bit one under its own `WOW6432Node`
    /// spelling), so the 32-bit key counts as Windows' own only when the baseline has that very
    /// spelling. Every other key (all of Classes in either hive, `HKCR`, the shared or reflected
    /// subtrees, anything that is not a 32-bit spelling) is answered exactly as [`Baseline::has_key`]
    /// answers it.
    ///
    /// This is the weaker proof and is meant only for a delete-if-empty vendor container; every other
    /// caller should keep asking [`Baseline::has_key`].
    pub fn has_key_exact_view(&self, key: &str) -> bool {
        let forms = key_forms(key);
        let take = if views_are_separate(&forms) {
            1
        } else {
            forms.len()
        };
        forms[..take]
            .iter()
            .any(|form| self.keys.binary_search(&hash(form.as_bytes())).is_ok())
    }

    /// Whether clean Windows has a value of this name in this key (`""` is the default value).
    pub fn has_value(&self, key: &str, name: &str) -> bool {
        self.value(key, name).is_some()
    }

    /// The type and data hash clean Windows has for this value.
    pub fn value(&self, key: &str, name: &str) -> Option<BaselineValue> {
        let name = prefix::fold(name);
        key_forms(key).iter().find_map(|form| {
            let id = value_id(hash(form.as_bytes()), &name);
            let at = self.values.binary_search_by_key(&id, |v| v.id).ok()?;
            let rec = self.values[at];
            Some(BaselineValue {
                ty: rec.ty,
                data_hash: rec.data_hash,
            })
        })
    }

    /// Whether the rig that writes baselines captures this key at all (`vm/RIG.md` §2). Outside the
    /// scope [`Baseline::has_key`] is always `false` and proves nothing.
    pub fn key_in_scope(key: &str) -> bool {
        key_forms(key).iter().any(|form| {
            if under(form, "hklm\\system\\currentcontrolset") {
                !under(form, "hklm\\system\\currentcontrolset\\enum")
                    && !under(
                        form,
                        "hklm\\system\\currentcontrolset\\control\\deviceclasses",
                    )
            } else {
                under(form, "hklm\\software") || form.starts_with("hku\\")
            }
        })
    }

    /// Whether the rig captures this path (`vm/RIG.md` §2): everything below the recursive roots, and
    /// the direct children of the depth-1 roots. Outside the scope [`Baseline::has_path`] is always
    /// `false` and proves nothing. Paths are compared on drive `C:`, as the baseline records them.
    pub fn path_in_scope(path: &str) -> bool {
        const RECURSIVE: [&str; 8] = [
            "c:\\program files",
            "c:\\program files (x86)",
            "c:\\programdata",
            "c:\\users",
            "c:\\windows\\installer",
            "c:\\windows\\prefetch",
            "c:\\windows\\system32\\tasks",
            "c:\\windows\\tasks",
        ];
        const DEPTH_1: [&str; 6] = [
            "c:",
            "c:\\windows",
            "c:\\windows\\system32",
            "c:\\windows\\syswow64",
            "c:\\windows\\system32\\drivers",
            "c:\\windows\\fonts",
        ];
        let norm = normalised_path(path);
        RECURSIVE.iter().any(|root| under(&norm, root))
            || DEPTH_1.iter().any(|root| {
                norm == *root
                    || norm
                        .strip_prefix(root)
                        .and_then(|rest| rest.strip_prefix('\\'))
                        .is_some_and(|child| !child.is_empty() && !child.contains('\\'))
            })
    }

    /// Whether clean Windows has this file or directory.
    pub fn has_path(&self, path: &str) -> bool {
        self.path_kind(path).is_some()
    }

    /// Whether clean Windows has this path, and as what.
    pub fn path_kind(&self, path: &str) -> Option<PathKind> {
        let mut norm = String::with_capacity(path.len());
        normalise_path(&prefix::fold(path), &mut norm);
        self.kind_of(&norm)
    }

    /// Like [`Baseline::path_kind`], for a host whose profile directory is not `X:\Users\<name>`: a
    /// `path` at or below `profile_dir` is compared with the baseline user's profile.
    pub fn has_profile_path(&self, profile_dir: &str, path: &str) -> bool {
        let mut dir = String::new();
        normalise_path(&prefix::fold(profile_dir), &mut dir);
        let mut norm = String::new();
        normalise_path(&prefix::fold(path), &mut norm);
        let below = match norm.strip_prefix(dir.as_str()) {
            Some(rest) if rest.is_empty() || rest.starts_with('\\') => rest,
            _ => return self.kind_of(&norm).is_some(),
        };
        // The baseline user's profile lives on the system drive of the baseline machine.
        let mapped = format!("c:\\users\\{USER_PLACEHOLDER}{below}");
        self.kind_of(&mapped).is_some() || self.kind_of(&norm).is_some()
    }

    /// Whether any key, file or directory of clean Windows has this last segment, or any value this name.
    ///
    /// This is the whole-segment test `HarvestedToken` needs ("absent from the baseline", §5.3): a token
    /// that is, for example, the name of a CLSID key Windows ships is not the app's own.
    pub fn has_segment(&self, name: &str) -> bool {
        self.leaves
            .binary_search(&hash(prefix::fold(name).as_bytes()))
            .is_ok()
    }

    /// Whether a GUID or hex token occurs in the baseline the way the reference matcher would find it
    /// (`crate::matcher`, "whole segment"): as a whole last segment or value name, bare or in braces, or
    /// as a delimited part of one (`Volume{GUID}`, `{GUID}.{GUID}`, `Prefix {GUID}`), where a part is a
    /// maximal run of letters, digits, `.`, `-` and `_`.
    pub fn has_token(&self, token: &str) -> bool {
        let bare = token.trim().trim_start_matches('{').trim_end_matches('}');
        !bare.is_empty()
            && (self.has_segment(bare)
                || self.has_segment(&format!("{{{bare}}}"))
                || self
                    .parts
                    .binary_search(&hash(prefix::fold(bare).as_bytes()))
                    .is_ok())
    }

    fn kind_of(&self, normalised: &str) -> Option<PathKind> {
        let h = hash(normalised.as_bytes());
        if self.dirs.binary_search(&h).is_ok() {
            Some(PathKind::Dir)
        } else if self.files.binary_search(&h).is_ok() {
            Some(PathKind::File)
        } else {
            None
        }
    }
}

/// The normalised form of a registry key, as the baseline compares it (see the module documentation).
/// Exposed for diagnostics and tests; queries normalise their arguments themselves.
pub fn normalised_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    normalise_key(&prefix::fold(key), &mut out);
    out
}

/// The normalised form of a file path, as the baseline compares it.
pub fn normalised_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    normalise_path(&prefix::fold(path), &mut out);
    out
}

fn parse_header(line: &[u8]) -> Result<Baseline, BaselineError> {
    let text = String::from_utf8_lossy(line).into_owned();
    let bad = || BaselineError::BadHeader(text.clone());
    let mut fields = text.split('\t');
    let (tag, version) = fields
        .next()
        .and_then(|f| f.split_once(' '))
        .ok_or_else(bad)?;
    if tag != HEADER_TAG {
        return Err(bad());
    }
    if version.trim().parse::<u32>().ok() != Some(FORMAT_VERSION) {
        return Err(BaselineError::UnsupportedVersion(version.to_owned()));
    }
    let (Some(time), Some(computer), Some(edition), Some(version)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(bad());
    };
    let (build, ubr) = version.trim().split_once('.').ok_or_else(bad)?;
    Ok(Baseline::empty(
        edition,
        build.parse().map_err(|_| bad())?,
        ubr.parse().map_err(|_| bad())?,
        time,
        computer,
        "",
    ))
}

/// The record lines of the baseline format (`K`, `V`, `D`, `F`; `kb/baselines/README.md`), hashed into
/// a [`Baseline`]'s sets. Shared by the exact loader ([`Baseline::from_reader`]) and the local
/// baseline's reader, which differ only in their header and trailer lines.
pub(crate) struct RecordParser {
    folded: Vec<u8>,
    norm: String,
}

impl RecordParser {
    pub(crate) fn new() -> RecordParser {
        RecordParser {
            folded: Vec::with_capacity(512),
            norm: String::with_capacity(512),
        }
    }

    /// Adds one record line (without its line end; neither empty nor a `#` line) to `out`. `line_no`
    /// is the 1-based line number the error names.
    pub(crate) fn add(
        &mut self,
        out: &mut Baseline,
        line: &[u8],
        line_no: u64,
    ) -> Result<(), BaselineError> {
        let bad = |reason: &'static str| BaselineError::BadRecord {
            line: line_no,
            reason,
        };
        let (folded, norm) = (&mut self.folded, &mut self.norm);
        if line.len() < 2 || line[1] != b'\t' {
            return Err(bad("no field after the record type"));
        }
        let mut fields = line[2..].split(|b| *b == b'\t');
        let first = fields.next().unwrap_or_default();
        let text = fold_field(first, folded).map_err(bad)?;
        match line[0] {
            b'K' => {
                normalise_key(text, norm);
                out.keys.push(hash(norm.as_bytes()));
                out.leaves.push(hash(leaf(norm).as_bytes()));
                push_parts(leaf(norm), &mut out.parts);
                out.counts.keys += 1;
            }
            b'V' => {
                normalise_key(text, norm);
                let key_hash = hash(norm.as_bytes());
                let (Some(name), Some(ty), Some(data)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Err(bad("a value record needs key, name, type and hash"));
                };
                let name = fold_field(name, folded).map_err(bad)?;
                let ty = parse_dec(ty).ok_or_else(|| bad("the value type is not a number"))?;
                let data_hash =
                    parse_hex(data).ok_or_else(|| bad("the value hash is not 16 hex digits"))?;
                out.values.push(ValueRec {
                    id: value_id(key_hash, name),
                    ty,
                    data_hash,
                });
                if !name.is_empty() {
                    out.leaves.push(hash(name.as_bytes()));
                    push_parts(name, &mut out.parts);
                }
                out.counts.values += 1;
            }
            b'D' | b'F' => {
                normalise_path(text, norm);
                let h = hash(norm.as_bytes());
                out.leaves.push(hash(leaf(norm).as_bytes()));
                push_parts(leaf(norm), &mut out.parts);
                if line[0] == b'D' {
                    out.dirs.push(h);
                    out.counts.dirs += 1;
                } else {
                    out.files.push(h);
                    out.counts.files += 1;
                }
            }
            _ => return Err(bad("unknown record type")),
        }
        Ok(())
    }
}

/// Reads one line without its terminator (`\n` or `\r\n`); `false` at the end of the input.
pub(crate) fn read_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<bool, BaselineError> {
    line.clear();
    if reader.read_until(b'\n', line)? == 0 {
        return Ok(false);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(true)
}

/// Undoes the file's escapes (`\\`, `\t`, `\n`, `\r`, `\0`) and folds the case, into `buf`.
fn fold_field<'a>(field: &[u8], buf: &'a mut Vec<u8>) -> Result<&'a str, &'static str> {
    buf.clear();
    let mut ascii = true;
    let mut bytes = field.iter().copied();
    while let Some(b) = bytes.next() {
        let b = if b == b'\\' {
            match bytes.next() {
                Some(b'\\') => b'\\',
                Some(b't') => b'\t',
                Some(b'n') => b'\n',
                Some(b'r') => b'\r',
                Some(b'0') => 0,
                _ => return Err("unknown escape sequence"),
            }
        } else {
            b
        };
        ascii &= b.is_ascii();
        buf.push(b.to_ascii_lowercase());
    }
    if !ascii {
        let folded = prefix::fold(std::str::from_utf8(buf).map_err(|_| "not UTF-8")?);
        buf.clear();
        buf.extend_from_slice(folded.as_bytes());
    }
    std::str::from_utf8(buf).map_err(|_| "not UTF-8")
}

fn parse_dec(field: &[u8]) -> Option<u32> {
    std::str::from_utf8(field).ok()?.parse().ok()
}

fn parse_hex(field: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(field).ok()?;
    (text.len() == 16).then(|| u64::from_str_radix(text, 16).ok())?
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn hash_from(seed: u64, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(seed, |h, b| (h ^ u64::from(*b)).wrapping_mul(FNV_PRIME))
}

fn hash(bytes: &[u8]) -> u64 {
    hash_from(FNV_OFFSET, bytes)
}

/// `path` is `root` or below it (both normalised).
fn under(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}

/// Whether the reference matcher treats `c` as part of a token (`crate::matcher`).
fn is_part_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// Hashes the delimited parts of a folded leaf that are not the leaf itself.
fn push_parts(leaf: &str, parts: &mut Vec<u64>) {
    for part in leaf.split(|c| !is_part_char(c)) {
        if !part.is_empty() && part.len() < leaf.len() {
            parts.push(hash(part.as_bytes()));
        }
    }
}

const HKLM_CLASSES: &str = "hklm\\software\\classes";
const HKU_CLASSES: &str = "hku\\<sid>_classes";
const WOW: &str = "\\wow6432node";

/// The direct children of `HKLM\SOFTWARE` that the 32-bit view does not keep a separate copy of, or
/// that hold shared or reflected subtrees: `Classes` (shared classes, and the `WOW6432Node\Classes`
/// link), `Clients`, `Policies` and `RegisteredApplications` (shared), and `Microsoft` (redirected, but
/// with many shared descendants). Below these a 32-bit spelling is always answered from its twin too.
/// `WOW6432Node` is listed as well: a view root nested in the view root is no vendor key, so a doubled
/// spelling (`WOW6432Node\WOW6432Node\Microsoft`) cannot slip a shared key past the folding.
const SHARED_SOFTWARE_KEYS: [&str; 6] = [
    "classes",
    "clients",
    "microsoft",
    "policies",
    "registeredapplications",
    "wow6432node",
];

/// Whether `forms` (of [`key_forms`]) are those of `HKLM\SOFTWARE\WOW6432Node\<x>[\…]` with `<x>` not in
/// [`SHARED_SOFTWARE_KEYS`]: a key of the 32-bit view that is stored separately from its 64-bit
/// namesake. The key's own spelling is then `forms[0]` and the twin `forms[1]`.
fn views_are_separate(forms: &[String]) -> bool {
    let [own, _twin] = forms else {
        return false;
    };
    own.strip_prefix("hklm\\software")
        .and_then(|rest| rest.strip_prefix(WOW))
        .and_then(|rest| rest.strip_prefix('\\'))
        .and_then(|rest| rest.split('\\').next())
        .is_some_and(|x| !x.is_empty() && !SHARED_SOFTWARE_KEYS.contains(&x))
}

/// The normalised spellings under which a queried key may be recorded: the key itself and, for a
/// 32-bit-view spelling, its 64-bit twin (see the module documentation). `HKCR` yields the machine and
/// the user classes.
fn key_forms(key: &str) -> Vec<String> {
    let folded = prefix::fold(key);
    let trimmed = folded.trim_start_matches('\\');
    let (root, rest) = trimmed.split_once('\\').unwrap_or((trimmed, ""));
    let starts: Vec<String> = if matches!(root, "hkcr" | "hkey_classes_root") {
        vec![
            format!("{HKLM_CLASSES}\\{rest}"),
            format!("{HKU_CLASSES}\\{rest}"),
        ]
    } else {
        vec![folded]
    };
    let mut forms = Vec::with_capacity(4);
    for start in starts {
        let mut norm = String::with_capacity(start.len());
        normalise_key(&start, &mut norm);
        let twin = [HKLM_CLASSES, HKU_CLASSES, "hklm\\software"]
            .iter()
            .find_map(|head| {
                let below = norm.strip_prefix(head)?.strip_prefix(WOW)?;
                (below.is_empty() || below.starts_with('\\')).then(|| format!("{head}{below}"))
            });
        forms.push(norm);
        forms.extend(twin);
    }
    forms
}

/// The id of a value: the key's hash continued over a byte that cannot occur in UTF-8 and the name.
fn value_id(key_hash: u64, folded_name: &str) -> u64 {
    hash_from(hash_from(key_hash, &[0xff]), folded_name.as_bytes())
}

fn leaf(normalised: &str) -> &str {
    normalised.rsplit('\\').next().unwrap_or(normalised)
}

/// `s-1-5-21-…` or `s-1-12-1-…` (lower case): a local, domain or Entra ID user.
fn is_user_sid(segment: &str) -> bool {
    let rest = segment
        .strip_prefix("s-1-5-21-")
        .or_else(|| segment.strip_prefix("s-1-12-1-"));
    rest.is_some_and(|r| {
        r.starts_with(|c: char| c.is_ascii_digit())
            && r.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    })
}

/// Rewrites `prefix` at the start of `key` (as whole segments) to `with`.
fn replace_head(key: &mut String, head: &str, with: &str) {
    if key.starts_with(head) && matches!(key.as_bytes().get(head.len()), None | Some(b'\\')) {
        key.replace_range(..head.len(), with);
    }
}

/// Writes the normalised form of an already folded key into `out`.
fn normalise_key(folded: &str, out: &mut String) {
    out.clear();
    for (i, segment) in folded.split('\\').filter(|s| !s.is_empty()).enumerate() {
        if i > 0 {
            out.push('\\');
        }
        match segment {
            "hkey_local_machine" if i == 0 => out.push_str("hklm"),
            "hkey_users" if i == 0 => out.push_str("hku"),
            "hkcu" | "hkey_current_user" if i == 0 => {
                out.push_str("hku\\");
                out.push_str(SID_PLACEHOLDER);
            }
            _ => match segment.strip_suffix("_classes") {
                Some(sid) if is_user_sid(sid) => {
                    out.push_str(SID_PLACEHOLDER);
                    out.push_str("_classes");
                }
                _ if is_user_sid(segment) => out.push_str(SID_PLACEHOLDER),
                _ => out.push_str(segment),
            },
        }
    }
    if out.starts_with("hklm\\system\\controlset") {
        let head = "hklm\\system\\controlset".len();
        let digits = out.as_bytes()[head..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 3 && matches!(out.as_bytes().get(head + 3), None | Some(b'\\')) {
            out.replace_range(
                .."hklm\\system\\controlset000".len(),
                "hklm\\system\\currentcontrolset",
            );
        }
    } else if out.starts_with("hku\\") {
        replace_head(out, "hku\\s-1-5-18", "hku\\.default");
        replace_head(
            out,
            "hku\\<sid>\\software\\wow6432node\\classes",
            "hku\\<sid>_classes\\wow6432node",
        );
        replace_head(out, "hku\\<sid>\\software\\classes", "hku\\<sid>_classes");
    } else {
        replace_head(
            out,
            "hklm\\software\\wow6432node\\classes",
            "hklm\\software\\classes\\wow6432node",
        );
    }
}

/// Profile directory names under `Users` that are the same on every machine.
const SHARED_PROFILES: [&str; 4] = ["default", "default user", "public", "all users"];

/// Writes the normalised form of an already folded path into `out`.
fn normalise_path(folded: &str, out: &mut String) {
    out.clear();
    let body = folded
        .strip_prefix("\\\\?\\")
        .or_else(|| folded.strip_prefix("\\??\\"))
        .unwrap_or(folded);
    let mut segments = body.split(['\\', '/']).filter(|s| !s.is_empty());
    let Some(drive) = segments.next() else { return };
    out.push_str(drive);
    let is_drive = drive.len() == 2 && drive.ends_with(':');
    for (i, segment) in segments.enumerate() {
        out.push('\\');
        let profile = is_drive
            && i == 1
            && out.ends_with(":\\users\\")
            && !SHARED_PROFILES.contains(&segment);
        out.push_str(if profile { USER_PLACEHOLDER } else { segment });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Instant;

    const SYNTHETIC: &str = include_str!("../tests/fixtures/Synthetic-12345.678.tsv");

    fn synthetic() -> Baseline {
        Baseline::from_bytes(SYNTHETIC.as_bytes()).expect("the synthetic baseline parses")
    }

    fn gzip(text: &str) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text.as_bytes()).unwrap();
        enc.finish().unwrap()
    }

    /// A fresh directory holding the synthetic baseline under its proper name.
    fn fixture_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("purge-index-baseline-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(Baseline::file_name("Synthetic", 12345, 678)),
            gzip(SYNTHETIC),
        )
        .unwrap();
        dir
    }

    /// A baseline made of records given as unescaped fields.
    fn baseline_of(records: &[&[&str]]) -> Baseline {
        let mut text = String::from("#purge-baseline 1\tT\tPC\tSynthetic\t1.2\n");
        for record in records {
            let fields: Vec<String> = record.iter().map(|f| f.replace('\\', "\\\\")).collect();
            text.push_str(&fields.join("\t"));
            text.push('\n');
        }
        Baseline::from_bytes(text.as_bytes()).expect("the records parse")
    }

    fn kb_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines")
    }

    #[test]
    fn synthetic_header_and_counts() {
        let b = synthetic();
        assert_eq!(b.edition(), "Synthetic");
        assert_eq!((b.build(), b.ubr()), (12345, 678));
        assert_eq!(b.computer(), "TEST-PC");
        assert_eq!(b.captured_at(), "2026-11-12T00:00:00Z");
        assert_eq!(b.source(), "tests/fixtures/snap-synthetic-0.tsv.gz");
        assert_eq!(
            b.counts(),
            RecordCounts {
                keys: 13,
                values: 9,
                dirs: 4,
                files: 3
            }
        );
        assert_eq!(
            SYNTHETIC.lines().count(),
            31,
            "header, source and 29 records"
        );
    }

    #[test]
    fn keys_are_case_insensitive_and_exact() {
        let b = synthetic();
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\.txt"));
        assert!(b.has_key(r"hklm\software\CLASSES\.TXT"));
        assert!(b.has_key(r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.txt\"));
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\.tx"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\.txt\ShellNew"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\.py"));
        // A key name may hold a forward slash; it is not a separator.
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\text/plain"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\MIME\Database\Content Type\text\plain"));
        assert!(!b.has_key(""));
        assert!(!b.has_key(r"HKXX\.txt"));
    }

    /// Unbound views fail closed: a key Windows ships must not look absent because of its spelling.
    #[test]
    fn unbound_views_fail_closed() {
        let b = synthetic();
        assert!(b.has_key(r"HKCR\.txt"));
        assert!(b.has_key(r"HKEY_CLASSES_ROOT\.txt\OpenWithProgids"));
        assert!(b.has_value(r"HKCR\.txt", "Content Type"));
        assert!(b.has_key(r"HKCR\Local Settings"), "the user's classes");
        assert!(!b.has_key(r"HKCR\.py"));
        assert!(b.has_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"));
        assert!(b.has_key(r"HKEY_CURRENT_USER\Software\Classes\Local Settings"));
        assert!(b.has_value(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "OneDriveSetup"
        ));
        assert!(!b.has_key(r"HKCU\Software\Vendor"));
    }

    /// The 32-bit view: the `WOW6432Node\Classes` link, and keys shared with the 64-bit view.
    #[test]
    fn wow6432node_spellings() {
        let b = baseline_of(&[
            &["K", r"HKLM\SOFTWARE\Classes\.txt"],
            &["K", r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}"],
            &[
                "V",
                r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}",
                "",
                "1",
                "0123456789abcdef",
            ],
            &["K", r"HKLM\SOFTWARE\WOW6432Node\Classes"],
            &["K", r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Only32"],
            &["K", r"HKLM\SOFTWARE\Microsoft\Shared"],
            &[
                "K",
                r"HKU\S-1-5-21-1-2-3-1000_Classes\WOW6432Node\CLSID\{B}",
            ],
            &["K", r"HKU\S-1-5-21-1-2-3-1000_Classes\.user"],
        ]);
        // The link and its target are one key.
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}"));
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{a}"));
        assert!(b.has_value(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{A}", ""));
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Classes"));
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\WOW6432Node"));
        // A shared key reached through the 32-bit view (the spelling `TypedTarget::key_path` gives).
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Classes\.txt"));
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\WOW6432Node\.txt"));
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Shared"));
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Only32"));
        assert!(b.has_key(r"HKCR\WOW6432Node\CLSID\{A}"));
        let sid = "S-1-5-21-9-9-9-1001";
        assert!(b.has_key(&format!(r"HKU\{sid}_Classes\WOW6432Node\CLSID\{{B}}")));
        assert!(b.has_key(&format!(
            r"HKU\{sid}\Software\Classes\WOW6432Node\CLSID\{{B}}"
        )));
        assert!(b.has_key(&format!(
            r"HKU\{sid}\Software\WOW6432Node\Classes\CLSID\{{B}}"
        )));
        assert!(b.has_key(&format!(r"HKU\{sid}_Classes\WOW6432Node\.user")));
        // The twin rule goes one way only, and only for whole segments.
        assert!(!b.has_key(r"HKLM\SOFTWARE\Microsoft\Only32"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\CLSID\{A}"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Classes\.py"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\WOW6432NodeX\Microsoft\Shared"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Vendor"));
    }

    /// A vendor key of the 32-bit view is its own key: the exact-view query does not answer it from the
    /// 64-bit twin, and answers everything else as `has_key` does.
    #[test]
    fn exact_view_separates_only_software_vendor_keys() {
        let b = baseline_of(&[
            &["K", r"HKLM\SOFTWARE\Mozilla"],
            &["K", r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts"],
            &["K", r"HKLM\SOFTWARE\WOW6432Node\Both"],
            &["K", r"HKLM\SOFTWARE\Both"],
            &["K", r"HKLM\SOFTWARE\WOW6432Node\Only32"],
            &["K", r"HKLM\SOFTWARE\Classes\.txt"],
            &["K", r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}"],
            &["K", r"HKLM\SOFTWARE\Microsoft\Shared"],
            &["K", r"HKLM\SOFTWARE\Policies\Vendor"],
            &["K", r"HKLM\SOFTWARE\Clients\Mail"],
            &["K", r"HKLM\SOFTWARE\RegisteredApplications"],
            &["K", r"HKU\S-1-5-21-1-2-3-1000_Classes\.user"],
            &["K", r"HKU\S-1-5-21-1-2-3-1000\Software\Vendor"],
        ]);
        // The general query still folds the views.
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Mozilla"));
        // The exact one does not, for a vendor key and below it, however it is spelled.
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Mozilla"));
        assert!(!b.has_key_exact_view(r"hkey_local_machine\software\wow6432node\MOZILLA\"));
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Mozilla\NativeMessagingHosts"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\Mozilla"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts"));
        // A 32-bit key the baseline records under its own spelling is Windows' own.
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Both"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Only32"));
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\Only32"));
        // Classes stay folded: the K32 spelling, the link, shared keys, HKCR, the user's classes.
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{A}"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\Classes\WOW6432Node\.txt"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Classes\.txt"));
        assert!(b.has_key_exact_view(r"HKCR\WOW6432Node\.txt"));
        assert!(b.has_key_exact_view(r"HKCR\WOW6432Node\CLSID\{A}"));
        let sid = "S-1-5-21-9-9-9-1001";
        assert!(b.has_key_exact_view(&format!(r"HKU\{sid}_Classes\WOW6432Node\.user")));
        assert!(b.has_key_exact_view(&format!(r"HKU\{sid}\Software\Vendor")));
        // So do the shared and reflected subtrees of HKLM\SOFTWARE, and the view root itself.
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Shared"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Policies\Vendor"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Clients\Mail"));
        assert!(b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\RegisteredApplications"));
        assert_eq!(
            b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node"),
            b.has_key(r"HKLM\SOFTWARE\WOW6432Node")
        );
        // Whole segments only, and never more permissive than `has_key`.
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432NodeX\Mozilla"));
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Absent"));
        assert!(!b.has_key_exact_view(""));
    }

    /// The exact-view query never says "absent" where `has_key` says "present", except for the one
    /// shape it exists for; a doubled view root or an odd spelling of a shared key does not qualify.
    #[test]
    fn exact_view_is_never_weaker_outside_vendor_keys() {
        let b = baseline_of(&[
            &["K", r"HKLM\SOFTWARE\Vendor"],
            &["K", r"HKLM\SOFTWARE\Microsoft\Shared"],
            &["K", r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Shared"],
            &["K", r"HKLM\SOFTWARE\Policies\Microsoft"],
            &["K", r"HKLM\SOFTWARE\Classes\CLSID\{A}"],
            &["K", r"HKLM\SOFTWARE\RegisteredApplications"],
            &["K", r"HKLM\SYSTEM\CurrentControlSet\Services\X"],
            &["K", r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft"],
        ]);
        for key in [
            r"HKLM\SOFTWARE\WOW6432Node\WOW6432Node\Microsoft\Shared",
            r"HKLM\\SOFTWARE\\WOW6432Node\\MICROSOFT\\Shared\",
            r"\HKEY_LOCAL_MACHINE\Software\Wow6432Node\Policies\Microsoft",
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{A}",
            r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}",
            r"HKCR\WOW6432Node\CLSID\{A}",
            r"HKCR\CLSID\{A}",
            r"HKLM\SOFTWARE\WOW6432Node\RegisteredApplications",
            r"HKLM\SOFTWARE\Vendor",
            r"HKLM\SYSTEM\ControlSet001\Services\X",
            r"HKCU\Software\Microsoft",
        ] {
            assert!(b.has_key(key), "{key}");
            assert!(b.has_key_exact_view(key), "{key}");
        }
        // The one difference: a vendor key directly below the 32-bit view root, and its subtree.
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Vendor"));
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Vendor"));
    }

    #[test]
    fn scope_of_the_capture() {
        for key in [
            r"HKLM\SOFTWARE",
            r"HKLM\SOFTWARE\Vendor\App",
            r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\X",
            r"HKU\S-1-5-21-1-2-3-1000\Software\Vendor",
            r"HKU\.DEFAULT\Environment",
            r"HKCR\.txt",
            r"HKCU\Software",
        ] {
            assert!(Baseline::key_in_scope(key), "{key}");
        }
        for key in [
            r"HKLM\SYSTEM\Setup",
            r"HKLM\SYSTEM\MountedDevices",
            r"HKLM\SYSTEM",
            r"HKLM\SOFTWAREX",
            r"HKLM\SAM\SAM",
            r"HKLM\SYSTEM\CurrentControlSet\Enum\USB",
            r"HKLM\SYSTEM\ControlSet001\Control\DeviceClasses\{x}",
            r"HKLM",
            "",
        ] {
            assert!(!Baseline::key_in_scope(key), "{key}");
        }
        for path in [
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\Program Files (x86)",
            r"C:\ProgramData\Vendor",
            r"C:\Users\kim\AppData\Local\X",
            r"C:\Windows\Installer\{x}\a.msi",
            r"C:\Windows\System32\Tasks\Vendor\Task",
            r"C:\",
            r"C:\Tools",
            r"C:\Windows",
            r"C:\Windows\notepad.exe",
            r"C:\Windows\System32\drivers\x.sys",
            r"c:/windows/fonts/arial.ttf",
        ] {
            assert!(Baseline::path_in_scope(path), "{path}");
        }
        for path in [
            r"C:\Tools\App",
            r"C:\Windows\INF\x.inf",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\config\systemprofile",
            r"C:\Program Files2\X",
            r"D:\Program Files\X",
            "",
        ] {
            assert!(!Baseline::path_in_scope(path), "{path}");
        }
    }

    #[test]
    fn values_including_default_and_escaped_names() {
        let b = synthetic();
        assert!(b.has_value(r"HKLM\SOFTWARE\Classes\.txt", ""));
        assert!(b.has_value(r"HKLM\SOFTWARE\Classes\.txt", "content type"));
        assert!(b.has_value(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "txtfile"));
        assert!(!b.has_value(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "VSCode.txt"));
        assert!(!b.has_value(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", ""));
        // The key of a value need not have a K record of its own for the value to be known.
        assert!(b.has_value(r"HKLM\SOFTWARE\Classes\txtfile\shell\open\command", ""));
        // `\\`, `\t` and non-ASCII letters in a value name.
        assert!(b.has_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "C:\\Tools\\a\tb"
        ));
        assert!(b.has_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "ÜBER GRÖßE"
        ));
        assert!(b.has_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "über größe"
        ));
        assert!(!b.has_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "C:\\Tools\\a b"
        ));

        let v = b
            .value(r"HKLM\SOFTWARE\Classes\.txt", "Content Type")
            .unwrap();
        assert_eq!(v.ty, 1);
        assert_eq!(v.hash_hex(), "0123456789abcdef");
        assert_eq!(
            b.value(r"HKLM\SOFTWARE\Classes\.txt", "PerceivedType"),
            None
        );
    }

    #[test]
    fn control_set_spellings_are_one_key() {
        let b = synthetic();
        for key in [
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip",
            r"HKLM\SYSTEM\ControlSet001\Services\Tcpip",
            r"HKLM\SYSTEM\ControlSet002\Services\tcpip",
        ] {
            assert!(b.has_key(key), "{key}");
            assert!(b.has_value(key, "ImagePath"), "{key}");
        }
        // The file itself may use the numbered spelling.
        assert!(b.has_key(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"));
        assert!(b.has_value(
            r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment",
            "Path"
        ));
        // Only the control-set segment itself is rewritten.
        assert!(!b.has_key(r"HKLM\SYSTEM\ControlSet0011\Services\Tcpip"));
        assert!(!b.has_key(r"HKLM\SYSTEM\ControlSetXYZ\Services\Tcpip"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\ControlSet001\Services\Tcpip"));
        assert_eq!(
            normalised_key(r"HKLM\SYSTEM\ControlSet001"),
            r"hklm\system\currentcontrolset"
        );
    }

    #[test]
    fn sid_placeholder_matches_any_user() {
        let b = synthetic();
        // The baseline machine's own user, a user of another machine, and an Entra ID user.
        for sid in [
            "S-1-5-21-1111111111-2222222222-3333333333-1000",
            "S-1-5-21-1004336348-1177238915-682003330-1001",
            "s-1-12-1-1234567890-1234567890-1234567890-1234567890",
        ] {
            assert!(b.has_key(&format!(
                r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Run"
            )));
            assert!(b.has_value(
                &format!(r"HKEY_USERS\{sid}\Software\Microsoft\Windows\CurrentVersion\Run"),
                "OneDriveSetup"
            ));
            assert!(b.has_key(&format!(r"HKU\{sid}_Classes\Local Settings")));
            // The classes hive reached through its link.
            assert!(b.has_key(&format!(r"HKU\{sid}\Software\Classes\Local Settings")));
            // A per-user key inside HKLM.
            assert!(b.has_key(&format!(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"
            )));
            assert!(!b.has_key(&format!(r"HKU\{sid}\Software\Vendor")));
        }
        // Service accounts are not users.
        assert!(!b.has_key(r"HKU\S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Run"));
        assert!(b.has_key(r"HKU\S-1-5-19\Environment"));
        assert!(!b.has_key(r"HKU\S-1-5-21-1-2-3-1000\Environment"));
        // LocalSystem's hive has two names.
        assert!(b.has_key(r"HKU\.DEFAULT\Environment"));
        assert!(b.has_key(r"HKU\S-1-5-18\Environment"));
        assert!(!b.has_key(r"HKU\S-1-5-180\Environment"));
        assert_eq!(
            normalised_key(r"HKU\S-1-5-21-1-2-3-1000\Software\Classes\.txt"),
            r"hku\<sid>_classes\.txt"
        );
        assert_eq!(
            normalised_key(r"HKU\S-1-5-21-1-2-3-1000\Software\ClassesX"),
            r"hku\<sid>\software\classesx"
        );
        assert_eq!(
            normalised_key(r"HKU\S-1-5-21-x\Software"),
            r"hku\s-1-5-21-x\software"
        );
    }

    #[test]
    fn paths_and_profile_placeholder() {
        let b = synthetic();
        assert_eq!(b.path_kind(r"C:\Windows\System32"), Some(PathKind::Dir));
        assert_eq!(
            b.path_kind(r"c:\windows\system32\NOTEPAD.EXE"),
            Some(PathKind::File)
        );
        assert_eq!(
            b.path_kind(r"\\?\C:\Windows\System32\notepad.exe"),
            Some(PathKind::File)
        );
        assert_eq!(b.path_kind("C:/Windows/System32/"), Some(PathKind::Dir));
        assert_eq!(b.path_kind(r"C:\Windows\System32\calc.exe"), None);
        assert_eq!(b.path_kind(r"C:\Windows\System3"), None);
        assert!(b.has_path(r"C:\Program Files\Common Files"));
        assert!(!b.has_path(r"C:\Program Files\Common Files\Vendor"));
        assert!(!b.has_path(r"D:\Windows\System32"));

        // Another user's profile matches the baseline user's; shared profiles are literal.
        assert!(b.has_path(r"C:\Users\someone else\AppData\Local\Microsoft"));
        assert!(b.has_path(r"C:\Users\someone else\NTUSER.DAT"));
        assert!(b.has_path(r"C:\Users\Public\Desktop"));
        assert!(!b.has_path(r"C:\Users\Public\AppData\Local\Microsoft"));
        assert!(!b.has_path(r"C:\Users\someone else\Desktop"));
        assert!(!b.has_path(r"C:\Users\someone else\AppData\Local\Vendor"));

        // A redirected profile.
        assert!(b.has_profile_path(
            r"D:\Profiles\kim",
            r"D:\Profiles\kim\AppData\Local\Microsoft"
        ));
        assert!(!b.has_path(r"D:\Profiles\kim\AppData\Local\Microsoft"));
        assert!(!b.has_profile_path(
            r"D:\Profiles\kim",
            r"D:\Profiles\kimberley\AppData\Local\Microsoft"
        ));
        assert!(!b.has_profile_path(r"D:\Profiles\kim", r"D:\Profiles\kim\AppData\Local\Vendor"));
        assert!(b.has_profile_path(r"D:\Profiles\kim", r"C:\Windows\System32"));
        assert_eq!(
            normalised_path(r"C:\Users\Kim\Documents\"),
            r"c:\users\<user>\documents"
        );
    }

    #[test]
    fn segments_and_tokens() {
        let b = synthetic();
        assert!(b.has_segment("{00021401-0000-0000-C000-000000000046}"));
        assert!(b.has_token("00021401-0000-0000-c000-000000000046"));
        assert!(b.has_token("{00021401-0000-0000-C000-000000000046}"));
        assert!(b.has_segment("OneDriveSetup"), "value names count");
        assert!(b.has_segment("notepad.exe"), "file names count");
        assert!(b.has_segment("txtfile"));
        assert!(!b.has_token("308046B0AF4A39CB"));
        assert!(!b.has_segment("0002140"), "whole segments only");
        assert!(!b.has_token(""));
        assert!(!b.has_token("{}"));

        // A token inside a composite name is found the way the reference matcher delimits it.
        let c = baseline_of(&[
            &[
                "K",
                r"HKLM\SOFTWARE\X\Volume{27190149-88D9-4FB3-9465-E160B9D588F7}",
            ],
            &["K", r"HKLM\SOFTWARE\X\FirefoxURL-308046B0AF4A39CB"],
            &[
                "V",
                r"HKLM\SOFTWARE\X",
                r"C:\Dir\AAAABBBBCCCCDDDD\x.dll",
                "1",
                "0123456789abcdef",
            ],
            &[
                "F",
                r"C:\ProgramData\X\{11111111-2222-3333-4444-555555555555}.{66666666-2222-3333-4444-555555555555}",
            ],
        ]);
        assert!(c.has_token("27190149-88d9-4fb3-9465-e160b9d588f7"));
        assert!(c.has_token("{27190149-88D9-4FB3-9465-E160B9D588F7}"));
        assert!(
            c.has_token("AAAABBBBCCCCDDDD"),
            "a segment of a value name that is a path"
        );
        assert!(c.has_token("11111111-2222-3333-4444-555555555555"));
        assert!(c.has_token("66666666-2222-3333-4444-555555555555"));
        // `-` does not delimit, exactly as in the matcher.
        assert!(!c.has_token("308046B0AF4A39CB"));
        assert!(c.has_token("FirefoxURL-308046B0AF4A39CB"));
        assert!(!c.has_token("27190149"));
    }

    #[test]
    fn selection_requires_an_exact_match() {
        let dir = fixture_dir("select");
        let hit = Baseline::select(&dir, "Synthetic", 12345, 678).expect("exact match");
        assert!(hit.is_for("synthetic", 12345, 678));
        assert_eq!(hit.counts().keys, 13);
        assert!(
            Baseline::select(&dir, "Synthetic", 12345, 679).is_none(),
            "wrong ubr"
        );
        assert!(
            Baseline::select(&dir, "Synthetic", 12346, 678).is_none(),
            "wrong build"
        );
        assert!(
            Baseline::select(&dir, "Professional", 12345, 678).is_none(),
            "wrong edition"
        );
        assert!(Baseline::select(&dir, "", 12345, 678).is_none());
        assert!(Baseline::select(&dir, r"..\Synthetic", 12345, 678).is_none());
        assert!(Baseline::select(&dir.join("missing"), "Synthetic", 12345, 678).is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_named_for_another_build_is_refused() {
        let dir = fixture_dir("mismatch");
        fs::copy(
            dir.join(Baseline::file_name("Synthetic", 12345, 678)),
            dir.join(Baseline::file_name("Synthetic", 12345, 999)),
        )
        .unwrap();
        assert!(Baseline::select(&dir, "Synthetic", 12345, 999).is_none());
        assert!(matches!(
            Baseline::try_select(&dir, "Synthetic", 12345, 999),
            Err(BaselineError::HeaderMismatch { .. })
        ));
        fs::write(
            dir.join(Baseline::file_name("Broken", 1, 2)),
            b"not a baseline",
        )
        .unwrap();
        assert!(Baseline::select(&dir, "Broken", 1, 2).is_none());
        assert!(matches!(
            Baseline::try_select(&dir, "Broken", 1, 2),
            Err(BaselineError::BadHeader(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_input_is_an_error() {
        let header = "#purge-baseline 1\t2026-11-12T00:00:00Z\tPC\tSynthetic\t1.2\n";
        let parse = |body: &str| Baseline::from_bytes(format!("{header}{body}").as_bytes());
        assert!(parse("K\tHKLM\\\\SOFTWARE\n").is_ok());
        assert!(
            parse("K\tHKLM\\\\SOFTWARE\r\n\r\n").is_ok(),
            "CRLF and blank lines are tolerated"
        );
        assert!(matches!(
            parse("K\tHKLM\\\\SOFTWARE\nX\tfoo\n"),
            Err(BaselineError::BadRecord { line: 3, .. })
        ));
        assert!(matches!(
            parse("K\tHKLM\\xSOFTWARE\n"),
            Err(BaselineError::BadRecord { line: 2, .. })
        ));
        assert!(matches!(
            parse("K\tHKLM\\"),
            Err(BaselineError::BadRecord { .. })
        ));
        assert!(matches!(
            parse("V\tHKLM\\\\S\tname\t1\n"),
            Err(BaselineError::BadRecord { .. })
        ));
        assert!(matches!(
            parse("V\tHKLM\\\\S\tname\tx\t0123456789abcdef\n"),
            Err(BaselineError::BadRecord { .. })
        ));
        assert!(matches!(
            parse("V\tHKLM\\\\S\tname\t1\t0123\n"),
            Err(BaselineError::BadRecord { .. })
        ));
        assert!(matches!(parse("K\n"), Err(BaselineError::BadRecord { .. })));
        assert!(matches!(
            Baseline::from_bytes(b"#purge-baseline 2\tT\tPC\tSynthetic\t1.2\n"),
            Err(BaselineError::UnsupportedVersion(_))
        ));
        assert!(matches!(
            Baseline::from_bytes(b"#purge-baseline 1\tT\tPC\tSynthetic\t12\n"),
            Err(BaselineError::BadHeader(_))
        ));
        assert!(matches!(
            Baseline::from_bytes(b""),
            Err(BaselineError::BadHeader(_))
        ));
        assert!(matches!(
            Baseline::from_bytes(&[0x1f, 0x8b, 0, 0]),
            Err(BaselineError::Io(_))
        ));
    }

    /// The record counts `kb/baselines/README.md` documents for a committed baseline.
    fn check_committed(edition: &str, build: u32, ubr: u32, counts: RecordCounts) -> Baseline {
        let started = Instant::now();
        let b = Baseline::try_select(&kb_dir(), edition, build, ubr)
            .expect("the committed baseline is readable")
            .expect("the committed baseline exists");
        println!(
            "{edition}-{build}.{ubr}: loaded in {:?}, {:?}",
            started.elapsed(),
            b.counts()
        );
        assert_eq!(b.counts(), counts);
        assert!(b.source().starts_with("vm/runs/"));

        assert!(b.has_key(r"HKLM\SOFTWARE\Classes"));
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\.txt"));
        assert!(b.has_key(r"HKLM\SOFTWARE\Classes\CLSID\{00021401-0000-0000-C000-000000000046}"));
        assert!(b.has_token("00021401-0000-0000-C000-000000000046"));
        assert!(b.has_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
        assert!(b.has_key(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip"));
        assert!(b.has_key(r"HKLM\SYSTEM\ControlSet001\Services\Tcpip"));
        assert!(b.has_value(r"HKLM\SYSTEM\ControlSet001\Services\Tcpip", "ImagePath"));
        // The exact-view query on a real capture: the 32-bit keys Windows ships are recorded under
        // their own spelling and stay Windows' own, as do the shared subtrees; only a vendor key that
        // exists in the 64-bit view alone is told apart.
        for key in [
            r"HKLM\SOFTWARE\WOW6432Node",
            r"HKLM\SOFTWARE\WOW6432Node\ODBC",
            r"HKLM\SOFTWARE\WOW6432Node\Intel",
            r"HKLM\SOFTWARE\WOW6432Node\Oracle",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Policies",
            r"HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft",
            r"HKLM\SOFTWARE\WOW6432Node\Clients",
            r"HKLM\SOFTWARE\WOW6432Node\RegisteredApplications",
            r"HKLM\SOFTWARE\WOW6432Node\Classes",
            r"HKLM\SOFTWARE\WOW6432Node\Classes\.txt",
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{00021401-0000-0000-C000-000000000046}",
            r"HKLM\SOFTWARE\Mozilla",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ] {
            assert!(b.has_key(key), "{key}");
            assert!(b.has_key_exact_view(key), "{key}");
        }
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Mozilla"));
        assert!(!b.has_key_exact_view(r"HKLM\SOFTWARE\WOW6432Node\Mozilla"));
        assert!(b.has_key(r"HKU\.DEFAULT\Control Panel\Accessibility\HighContrast"));
        assert!(b.has_value(
            r"HKU\S-1-5-18\Control Panel\Accessibility\HighContrast",
            "Flags"
        ));
        // Another machine's user.
        let sid = "S-1-5-21-1004336348-1177238915-682003330-1001";
        assert!(b.has_key(&format!(
            r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer"
        )));
        assert!(b.has_key(&format!(r"HKU\{sid}_Classes\Local Settings")));
        assert!(b.has_key(&format!(r"HKU\{sid}\Software\Classes\Local Settings")));
        assert!(b.has_path(r"C:\Users\Public"));
        assert!(b.has_path(r"C:\Users\Default"));
        assert!(b.has_path(r"C:\Users\tester"));
        assert!(
            b.has_path(r"C:\Users\Somebody Else"),
            "the profile directory of any user"
        );

        // Things no clean Windows has.
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\VSCode.txt"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Mozilla\Firefox"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids"));
        assert!(!b.has_value(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "VSCode.txt"));
        assert!(!b.has_key(&format!(r"HKU\{sid}\Software\Mozilla\Firefox\TaskBarIDs")));
        assert!(!b.has_path(r"C:\Program Files\Git"));
        assert!(!b.has_token("308046B0AF4A39CB"));

        // 32-bit view spellings of keys Windows ships (`.txt` is shared with the 64-bit view).
        let shell_link = r"CLSID\{00021401-0000-0000-C000-000000000046}";
        assert!(b.has_key(&format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\{shell_link}")));
        assert!(b.has_key(&format!(r"HKLM\SOFTWARE\WOW6432Node\Classes\{shell_link}")));
        assert!(b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Classes\.txt"));
        assert!(b.has_key(r"HKCR\.txt"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Classes\VSCode.txt"));
        assert!(!b.has_key(r"HKLM\SOFTWARE\WOW6432Node\Mozilla\Firefox"));
        b
    }

    #[test]
    fn loads_the_committed_enterprise_baseline() {
        check_committed(
            "EnterpriseSEval",
            26100,
            1742,
            RecordCounts {
                keys: 275_872,
                values: 460_215,
                dirs: 2_158,
                files: 15_050,
            },
        );
        assert!(Baseline::select(&kb_dir(), "EnterpriseSEval", 26100, 1743).is_none());
    }

    #[test]
    fn loads_the_committed_professional_baseline() {
        check_committed(
            "Professional",
            26340,
            9882,
            RecordCounts {
                keys: 309_932,
                values: 528_901,
                dirs: 6_001,
                files: 37_410,
            },
        );
        assert!(Baseline::select(&kb_dir(), "Professional", 26100, 1742).is_none());
    }

    /// Load time and size of the largest committed baseline. Run in release:
    /// `cargo test -p purge-index --release -- --ignored --nocapture professional_load_budget`.
    #[test]
    #[ignore = "timing; meaningful only with --release"]
    fn professional_load_budget() {
        let bytes =
            fs::read(kb_dir().join(Baseline::file_name("Professional", 26340, 9882))).unwrap();
        let mut best = std::time::Duration::MAX;
        let mut loaded = None;
        for _ in 0..3 {
            let started = Instant::now();
            loaded = Some(Baseline::from_bytes(&bytes).unwrap());
            best = best.min(started.elapsed());
        }
        let b = loaded.unwrap();
        let heap = 8
            * (b.keys.len() + b.dirs.len() + b.files.len() + b.leaves.len() + b.parts.len())
            + std::mem::size_of::<ValueRec>() * b.values.len();
        println!(
            "Professional: best of 3 = {best:?}, retained heap = {:.1} MB",
            heap as f64 / 1e6
        );
        assert!(heap < 150_000_000);
        if !cfg!(debug_assertions) {
            assert!(best.as_millis() < 1000, "load took {best:?}");
        }
    }
}
