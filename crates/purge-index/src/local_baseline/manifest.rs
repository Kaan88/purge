//! Component manifests (`C:\Windows\WinSxS\Manifests\*.manifest`, already expanded to XML) to local
//! baseline records: source S1 of BASELINE_LOCAL_DESIGN.md §3.1, mapped by the rules of §3.2.
//!
//! This is a pure parser: no I/O and no Windows call, so it runs on any CI machine. Expanding a
//! `DCM\x01` file to XML is `purge_win::sxs` (BL-WIN-SXS); building, sealing and writing the local
//! baseline is BL-BUILD. Real Microsoft manifests are never committed; the fixtures in
//! `tests/fixtures/manifests` are hand-written in their shape.
//!
//! # What is read
//!
//! A streaming reader (`quick-xml`) walks the document once. Elements and attributes are matched by
//! their local name, ASCII case-insensitively, so `registryKey`, `asm:registryKey` and
//! `asmv3:registryKey` are one element. Taken anywhere in the document:
//!
//! - `registryKey keyName=…` and the `registryValue name=… valueType=…` elements inside it;
//! - `file name=… destinationPath=…` (a file without `destinationPath` lives only in the component
//!   store and is counted, not recorded);
//! - `directory destinationPath=…`.
//!
//! The first `assemblyIdentity` directly below the root gives `processorArchitecture` (the
//! [`View`]) and `publicKeyToken` (kept in the stats for the measurement only: manifests of every
//! token are taken, L1). An `assemblyIdentity` elsewhere (inside `dependency`) names another component
//! and is not read.
//!
//! # Mapping (design §3.2)
//!
//! - Roots: `HKEY_LOCAL_MACHINE\X` (or `HKLM`) is `HKLM\X`; `HKEY_CLASSES_ROOT\X` (or `HKCR`) is
//!   `HKLM\SOFTWARE\Classes\X`; `HKEY_CURRENT_USER\X` (or `HKCU`) is recorded twice, as
//!   `HKU\S-1-5-21-0-0-0-1000\X` ([`HKCU_SID`]; the loader's normaliser turns it into `<sid>` and folds
//!   `Software\Classes`) and as `HKU\.DEFAULT\X`; `HKEY_USERS\X` (or `HKU`) is `HKU\X` as written. Any
//!   other root is skipped and counted.
//! - Every ancestor of a recorded key is recorded ([`Records`]).
//! - A `wow64` or `x86` manifest records each key under `HKLM\SOFTWARE` twice: as written and in the
//!   32-bit view, `HKLM\SOFTWARE\WOW6432Node\X`, or for Classes `HKLM\SOFTWARE\Classes\WOW6432Node\X`.
//!   The values of the key go with both. A key already spelled in the 32-bit view is not doubled again.
//! - Key names, value names and paths go through the macro table ([`super::macros`]). A key name with
//!   a macro outside the table is skipped (with its values) and counted; so is a value name or a path.
//!   Unknown macro names are listed in [`ManifestStats::unknown_macros`].
//! - Values: one `V` record per `registryValue`, type mapped from `valueType` (an unknown or missing
//!   type is recorded as `REG_NONE` and counted), no data hash. A `registryValue` outside any
//!   `registryKey` is counted, not recorded. A missing `name` is the default value.
//! - Files and directories: the expanded path must be absolute on a drive (`C:\…`), without `.` or `..`
//!   segments; the directories above a file or directory are recorded too.
//!
//! # Failure and bounds
//!
//! Malformed XML (a syntax error, mismatched or unclosed tags, a second root element, text outside
//! the root, a bad attribute or entity, invalid UTF-8 or UTF-16) is an error for the whole file, and
//! **nothing** from that file is added: the document is read completely before the first record is
//! written. Input is limited to [`MAX_MANIFEST_BYTES`], nesting to [`MAX_DEPTH`], items to
//! [`MAX_ITEMS`]; a key longer than [`MAX_KEY_BYTES`], a path longer than [`MAX_PATH_BYTES`], a value
//! name longer than [`MAX_VALUE_NAME_BYTES`] or a name with more than [`MAX_SEGMENTS`] segments is
//! skipped and counted; and the text the file could add with all ancestors is limited to
//! [`MAX_RECORD_BUDGET`]. No input makes the parser panic.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use super::macros::{self, View};
use super::records::Records;

/// The user SID an `HKEY_CURRENT_USER` key is recorded under; any user SID normalises to the same
/// placeholder in the loader.
pub const HKCU_SID: &str = "S-1-5-21-0-0-0-1000";

/// The largest manifest read (the expansion cap of `purge_win::sxs`); larger is [`ManifestError::TooLarge`].
pub const MAX_MANIFEST_BYTES: usize = 64 << 20;

/// The deepest element nesting accepted.
pub const MAX_DEPTH: usize = 256;

/// The most `registryKey`, `registryValue`, `file` and `directory` elements one manifest may hold.
pub const MAX_ITEMS: usize = 1_000_000;

/// The longest key name recorded (after mapping), in bytes.
pub const MAX_KEY_BYTES: usize = 2048;

/// The longest path recorded (after expansion), in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// The longest value name recorded, in bytes (the registry's limit is 16,383 characters).
pub const MAX_VALUE_NAME_BYTES: usize = 16_383 * 3;

/// The most segments a recorded key or path may have.
pub const MAX_SEGMENTS: usize = 64;

/// The bound on the text one manifest may add: the sum, over every recorded key and path, of its
/// length times its number of segments (which bounds the text of its ancestors), plus every value
/// name. Over this the file is [`ManifestError::TooMuchOutput`].
pub const MAX_RECORD_BUDGET: u64 = 256 << 20;

/// The most distinct unknown macro names kept in [`ManifestStats::unknown_macros`].
pub const MAX_UNKNOWN_NAMES: usize = 32;

/// The longest architecture or token text kept in the stats.
const MAX_IDENTITY_TEXT: usize = 64;

/// Why a manifest was not used. Nothing from it was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// More than [`MAX_MANIFEST_BYTES`].
    TooLarge {
        /// The input's size.
        bytes: usize,
    },
    /// Not UTF-8 (or UTF-16 with a byte-order mark).
    Encoding,
    /// The XML is not well-formed.
    Xml {
        /// Byte offset in the decoded text where the error was found.
        position: u64,
        /// What the reader reported.
        message: String,
    },
    /// An element is not closed at the end, or a second root element or text follows the root.
    Unbalanced,
    /// No root element.
    NoRoot,
    /// Elements nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// More than [`MAX_ITEMS`] items.
    TooManyItems,
    /// The records would exceed [`MAX_RECORD_BUDGET`].
    TooMuchOutput,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes } => write!(
                f,
                "manifest of {bytes} bytes exceeds {MAX_MANIFEST_BYTES} bytes"
            ),
            Self::Encoding => write!(f, "manifest is not UTF-8 or UTF-16 text"),
            Self::Xml { position, message } => {
                write!(f, "manifest XML at byte {position}: {message}")
            }
            Self::Unbalanced => write!(
                f,
                "manifest XML has an unclosed element or content after the root"
            ),
            Self::NoRoot => write!(f, "manifest XML has no root element"),
            Self::TooDeep => write!(f, "manifest XML nests deeper than {MAX_DEPTH} elements"),
            Self::TooManyItems => write!(f, "manifest has more than {MAX_ITEMS} items"),
            Self::TooMuchOutput => write!(f, "manifest would add too many records"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// What was left out of a manifest, by reason. Every count is of elements (or, for a value name with
/// several expansions, of names).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Skipped {
    /// Key names with a macro outside the table (the completeness seal's count, design §3.4).
    pub key_unknown_macro: u64,
    /// Value names with a macro outside the table.
    pub value_unknown_macro: u64,
    /// File and directory paths with a macro outside the table.
    pub path_unknown_macro: u64,
    /// Key names whose root is none of `HKEY_LOCAL_MACHINE`, `HKEY_CLASSES_ROOT`,
    /// `HKEY_CURRENT_USER`, `HKEY_USERS`.
    pub unknown_root: u64,
    /// Keys, paths and value names over the length or segment limits.
    pub too_long: u64,
    /// Paths that are not absolute on a drive, or hold a `.` or `..` segment.
    pub not_absolute: u64,
    /// Elements without the attribute they need (`keyName`; a file's `name`), and keys or paths that
    /// are only a root.
    pub incomplete: u64,
    /// `registryValue` elements outside any `registryKey`.
    pub orphan_values: u64,
    /// Values of a key that was skipped.
    pub values_of_skipped_keys: u64,
}

impl Skipped {
    /// The sum of every count.
    pub fn total(&self) -> u64 {
        self.key_unknown_macro
            + self.value_unknown_macro
            + self.path_unknown_macro
            + self.unknown_root
            + self.too_long
            + self.not_absolute
            + self.incomplete
            + self.orphan_values
            + self.values_of_skipped_keys
    }
}

/// What one manifest gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestStats {
    /// `processorArchitecture` of the manifest's own `assemblyIdentity` (at most 64 bytes).
    pub architecture: Option<String>,
    /// `publicKeyToken` of the manifest's own `assemblyIdentity` (at most 64 bytes), for the
    /// measurement only.
    pub public_key_token: Option<String>,
    /// The view the manifest was read in.
    pub view: View,
    /// `registryKey` elements.
    pub registry_keys: u64,
    /// `registryValue` elements.
    pub registry_values: u64,
    /// `file` elements.
    pub files: u64,
    /// `directory` elements.
    pub directories: u64,
    /// `file` elements without a destination (they live only in the component store).
    pub files_without_destination: u64,
    /// `registryValue` elements whose `valueType` is missing or unknown (recorded as `REG_NONE`).
    pub unknown_value_types: u64,
    /// What was skipped, by reason.
    pub skipped: Skipped,
    /// Unknown macro names and how often each was met (at most [`MAX_UNKNOWN_NAMES`] names).
    pub unknown_macros: BTreeMap<String, u64>,
    /// Unknown macros met after [`MAX_UNKNOWN_NAMES`] names were already listed.
    pub unknown_macros_unlisted: u64,
}

impl ManifestStats {
    fn note_unknown(&mut self, name: String) {
        if let Some(n) = self.unknown_macros.get_mut(&name) {
            *n += 1;
        } else if self.unknown_macros.len() < MAX_UNKNOWN_NAMES {
            self.unknown_macros.insert(name, 1);
        } else {
            self.unknown_macros_unlisted += 1;
        }
    }
}

/// Parses one manifest and adds its records to `records` (design §3.2). On an error nothing is added.
pub fn parse(xml: &[u8], records: &mut Records) -> Result<ManifestStats, ManifestError> {
    if xml.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge { bytes: xml.len() });
    }
    let text = decode(xml)?;
    let raw = collect(&text)?;
    let (pending, stats) = map(raw)?;
    pending.apply(records);
    Ok(stats)
}

// ---------------------------------------------------------------------------------------------------
// Decoding

fn decode(xml: &[u8]) -> Result<Cow<'_, str>, ManifestError> {
    if let Some(rest) = xml.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        utf8(rest)
    } else if let Some(rest) = xml.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, u16::from_le_bytes)
    } else if let Some(rest) = xml.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, u16::from_be_bytes)
    } else {
        utf8(xml)
    }
}

fn utf8(bytes: &[u8]) -> Result<Cow<'_, str>, ManifestError> {
    std::str::from_utf8(bytes)
        .map(Cow::Borrowed)
        .map_err(|_| ManifestError::Encoding)
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<Cow<'static, str>, ManifestError> {
    if bytes.len() % 2 != 0 {
        return Err(ManifestError::Encoding);
    }
    char::decode_utf16(bytes.chunks_exact(2).map(|c| unit([c[0], c[1]])))
        .collect::<Result<String, _>>()
        .map(Cow::Owned)
        .map_err(|_| ManifestError::Encoding)
}

// ---------------------------------------------------------------------------------------------------
// Reading the document

#[derive(Debug, Default)]
struct RawKey {
    name: String,
    values: Vec<RawValue>,
}

#[derive(Debug)]
struct RawValue {
    name: String,
    ty: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    Dir,
    File,
}

#[derive(Debug)]
struct RawPath {
    kind: PathKind,
    text: String,
}

/// Everything read from the document, before any mapping.
#[derive(Debug, Default)]
struct Raw {
    architecture: Option<String>,
    token: Option<String>,
    /// `None` for a `registryKey` without `keyName`.
    keys: Vec<Option<RawKey>>,
    paths: Vec<RawPath>,
    stats: ManifestStats,
}

fn xml_error(position: u64, e: impl fmt::Display) -> ManifestError {
    ManifestError::Xml {
        position,
        message: e.to_string(),
    }
}

fn is(name: &[u8], wanted: &str) -> bool {
    name.eq_ignore_ascii_case(wanted.as_bytes())
}

/// Reads every attribute of `e` (so that a malformed one is an error even on an element that is not
/// used) and hands the local name and normalised value of each to `f`.
fn each_attribute(
    e: &BytesStart<'_>,
    position: u64,
    mut f: impl FnMut(&[u8], Cow<'_, str>),
) -> Result<(), ManifestError> {
    for attr in e.attributes() {
        let attr = attr.map_err(|err| xml_error(position, err))?;
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| xml_error(position, err))?;
        f(attr.key.local_name().as_ref(), value);
    }
    Ok(())
}

fn capped(text: &str) -> String {
    let mut end = text.len().min(MAX_IDENTITY_TEXT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

struct Collector {
    raw: Raw,
    identity_seen: bool,
    /// (element depth, index into `raw.keys`) of every open `registryKey`.
    open_keys: Vec<(usize, usize)>,
    items: usize,
}

impl Collector {
    /// Handles the start of an element at `depth` (0 is the root).
    fn element(
        &mut self,
        e: &BytesStart<'_>,
        depth: usize,
        empty: bool,
        position: u64,
    ) -> Result<(), ManifestError> {
        let local = e.local_name();
        let name = local.as_ref();
        if is(name, "registryKey") {
            self.item()?;
            self.raw.stats.registry_keys += 1;
            let mut key = None;
            each_attribute(e, position, |attr, value| {
                if is(attr, "keyName") {
                    key = Some(value.into_owned());
                }
            })?;
            let index = self.raw.keys.len();
            self.raw.keys.push(key.map(|name| RawKey {
                name,
                values: Vec::new(),
            }));
            if !empty {
                self.open_keys.push((depth, index));
            }
        } else if is(name, "registryValue") {
            self.item()?;
            self.raw.stats.registry_values += 1;
            let (mut value_name, mut ty) = (None, None);
            each_attribute(e, position, |attr, value| {
                if is(attr, "name") {
                    value_name = Some(value.into_owned());
                } else if is(attr, "valueType") {
                    ty = Some(value.into_owned());
                }
            })?;
            match self.open_keys.last() {
                Some(&(_, index)) => match &mut self.raw.keys[index] {
                    Some(key) => key.values.push(RawValue {
                        name: value_name.unwrap_or_default(),
                        ty,
                    }),
                    None => self.raw.stats.skipped.values_of_skipped_keys += 1,
                },
                None => self.raw.stats.skipped.orphan_values += 1,
            }
        } else if is(name, "file") {
            self.item()?;
            self.raw.stats.files += 1;
            let (mut file, mut dest) = (None, None);
            each_attribute(e, position, |attr, value| {
                if is(attr, "name") {
                    file = Some(value.into_owned());
                } else if is(attr, "destinationPath") {
                    dest = Some(value.into_owned());
                }
            })?;
            let dest = dest
                .as_deref()
                .map(|d| d.trim().trim_end_matches(['\\', '/']))
                .filter(|d| !d.is_empty());
            match (
                dest,
                file.as_deref().map(str::trim).filter(|f| !f.is_empty()),
            ) {
                (None, _) => self.raw.stats.files_without_destination += 1,
                (Some(_), None) => self.raw.stats.skipped.incomplete += 1,
                (Some(dest), Some(file)) => self.raw.paths.push(RawPath {
                    kind: PathKind::File,
                    text: format!(r"{dest}\{file}"),
                }),
            }
        } else if is(name, "directory") {
            self.item()?;
            self.raw.stats.directories += 1;
            let mut dest = None;
            each_attribute(e, position, |attr, value| {
                if is(attr, "destinationPath") {
                    dest = Some(value.into_owned());
                }
            })?;
            match dest.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
                Some(dest) => self.raw.paths.push(RawPath {
                    kind: PathKind::Dir,
                    text: dest.to_owned(),
                }),
                None => self.raw.stats.skipped.incomplete += 1,
            }
        } else if is(name, "assemblyIdentity") && depth == 1 && !self.identity_seen {
            self.identity_seen = true;
            let (mut arch, mut token) = (None, None);
            each_attribute(e, position, |attr, value| {
                if is(attr, "processorArchitecture") {
                    arch = Some(capped(value.trim()));
                } else if is(attr, "publicKeyToken") {
                    token = Some(capped(value.trim()));
                }
            })?;
            self.raw.architecture = arch;
            self.raw.token = token;
        } else {
            each_attribute(e, position, |_, _| {})?;
        }
        Ok(())
    }

    fn item(&mut self) -> Result<(), ManifestError> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(ManifestError::TooManyItems);
        }
        Ok(())
    }

    /// Handles the end of the element at `depth`.
    fn end(&mut self, depth: usize) {
        if self.open_keys.last().is_some_and(|&(d, _)| d == depth) {
            self.open_keys.pop();
        }
    }
}

fn collect(text: &str) -> Result<Raw, ManifestError> {
    let mut reader = Reader::from_str(text);
    {
        let config = reader.config_mut();
        config.check_end_names = true;
        config.allow_unmatched_ends = false;
        config.expand_empty_elements = false;
    }
    let mut c = Collector {
        raw: Raw::default(),
        identity_seen: false,
        open_keys: Vec::new(),
        items: 0,
    };
    let mut depth = 0usize;
    let mut root_seen = false;
    loop {
        let position = reader.buffer_position();
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(e) => return Err(xml_error(reader.error_position(), e)),
        };
        match event {
            Event::Start(e) => {
                if depth == 0 {
                    if root_seen {
                        return Err(ManifestError::Unbalanced);
                    }
                    root_seen = true;
                }
                c.element(&e, depth, false, position)?;
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(ManifestError::TooDeep);
                }
            }
            Event::Empty(e) => {
                if depth == 0 {
                    if root_seen {
                        return Err(ManifestError::Unbalanced);
                    }
                    root_seen = true;
                }
                c.element(&e, depth, true, position)?;
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(ManifestError::Unbalanced)?;
                c.end(depth);
            }
            Event::Text(t) if depth == 0 => {
                if !t.iter().all(u8::is_ascii_whitespace) {
                    return Err(ManifestError::Unbalanced);
                }
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(ManifestError::Unbalanced);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ManifestError::Unbalanced);
    }
    if !root_seen {
        return Err(ManifestError::NoRoot);
    }
    Ok(c.raw)
}

// ---------------------------------------------------------------------------------------------------
// Mapping

/// One `registryKey` after mapping: every key spelling it is recorded under, and its values.
struct PendingKey {
    forms: Vec<String>,
    values: Vec<(String, u32)>,
}

/// The records of one manifest, complete before any is added.
#[derive(Default)]
struct Pending {
    keys: Vec<PendingKey>,
    dirs: Vec<String>,
    files: Vec<String>,
    budget: u64,
}

impl Pending {
    fn charge(&mut self, text: &str, segments: usize) -> Result<(), ManifestError> {
        let cost = u64::try_from(text.len().saturating_mul(segments.max(1))).unwrap_or(u64::MAX);
        self.budget = self.budget.saturating_add(cost);
        if self.budget > MAX_RECORD_BUDGET {
            return Err(ManifestError::TooMuchOutput);
        }
        Ok(())
    }

    fn apply(self, records: &mut Records) {
        for key in self.keys {
            for form in &key.forms {
                records.add_key(form);
                for (name, ty) in &key.values {
                    records.add_value(form, name, *ty);
                }
            }
        }
        for dir in &self.dirs {
            records.add_dir(dir);
        }
        for file in &self.files {
            records.add_file(file);
        }
    }
}

fn segments(text: &str) -> impl Iterator<Item = &str> {
    text.split(['\\', '/']).filter(|s| !s.is_empty())
}

/// The registry type of a `valueType`.
pub fn value_type(name: &str) -> Option<u32> {
    const TYPES: [(&str, u32); 14] = [
        ("REG_NONE", 0),
        ("REG_SZ", 1),
        ("REG_EXPAND_SZ", 2),
        ("REG_BINARY", 3),
        ("REG_DWORD", 4),
        ("REG_DWORD_LITTLE_ENDIAN", 4),
        ("REG_DWORD_BIG_ENDIAN", 5),
        ("REG_LINK", 6),
        ("REG_MULTI_SZ", 7),
        ("REG_RESOURCE_LIST", 8),
        ("REG_FULL_RESOURCE_DESCRIPTOR", 9),
        ("REG_RESOURCE_REQUIREMENTS_LIST", 10),
        ("REG_QWORD", 11),
        ("REG_QWORD_LITTLE_ENDIAN", 11),
    ];
    let name = name.trim();
    TYPES
        .iter()
        .find(|(t, _)| t.eq_ignore_ascii_case(name))
        .map(|(_, ty)| *ty)
}

enum KeySkip {
    UnknownRoot,
    RootOnly,
    TooLong,
}

/// Every spelling a key is recorded under: each macro expansion, mapped by its root (design §3.2),
/// and in a 32-bit manifest the twin in the 32-bit view.
fn key_forms(expanded: &[String], view: View) -> Result<Vec<String>, KeySkip> {
    let mut forms: Vec<String> = Vec::new();
    for name in expanded {
        for form in map_root(name)? {
            let twin = (view == View::Wow64).then(|| wow64_twin(&form)).flatten();
            for f in std::iter::once(form).chain(twin) {
                let text = f.join("\\");
                if text.len() > MAX_KEY_BYTES || f.len() > MAX_SEGMENTS {
                    return Err(KeySkip::TooLong);
                }
                if !forms.contains(&text) {
                    forms.push(text);
                }
            }
        }
    }
    Ok(forms)
}

/// The recorded spellings of one expanded key name (design §3.2 roots).
fn map_root(key: &str) -> Result<Vec<Vec<&str>>, KeySkip> {
    let mut parts = segments_of_key(key);
    let Some(root) = parts.next() else {
        return Err(KeySkip::RootOnly);
    };
    let rest: Vec<&str> = parts.collect();
    let with = |head: &[&'static str]| -> Vec<&str> {
        head.iter().copied().chain(rest.iter().copied()).collect()
    };
    let forms = if is(root.as_bytes(), "HKEY_LOCAL_MACHINE") || is(root.as_bytes(), "HKLM") {
        vec![with(&["HKLM"])]
    } else if is(root.as_bytes(), "HKEY_CLASSES_ROOT") || is(root.as_bytes(), "HKCR") {
        vec![with(&["HKLM", "SOFTWARE", "Classes"])]
    } else if is(root.as_bytes(), "HKEY_CURRENT_USER") || is(root.as_bytes(), "HKCU") {
        vec![with(&["HKU", HKCU_SID]), with(&["HKU", ".DEFAULT"])]
    } else if is(root.as_bytes(), "HKEY_USERS") || is(root.as_bytes(), "HKU") {
        vec![with(&["HKU"])]
    } else {
        return Err(KeySkip::UnknownRoot);
    };
    if forms.iter().any(|f| f.len() < 2) {
        return Err(KeySkip::RootOnly);
    }
    Ok(forms)
}

/// Registry key segments: only `\` separates (a key name may hold `/`).
fn segments_of_key(key: &str) -> impl Iterator<Item = &str> {
    key.split('\\').filter(|s| !s.is_empty())
}

/// The 32-bit view spelling of a mapped key under `HKLM\SOFTWARE`, if it is not one already.
fn wow64_twin<'a>(form: &[&'a str]) -> Option<Vec<&'a str>> {
    const WOW: &str = "WOW6432Node";
    let at = |i: usize, s: &str| form.get(i).is_some_and(|x| is(x.as_bytes(), s));
    if !(at(0, "HKLM") && at(1, "SOFTWARE")) {
        return None;
    }
    // `HKLM\SOFTWARE\Classes\X` -> `…\Classes\WOW6432Node\X`; `HKLM\SOFTWARE\X` -> `…\WOW6432Node\X`.
    let insert = if at(2, "Classes") { 3 } else { 2 };
    if at(insert, WOW) {
        return None;
    }
    let mut twin = form.to_vec();
    twin.insert(insert.min(twin.len()), WOW);
    Some(twin)
}

fn is_absolute(path: &str) -> bool {
    let mut parts = segments(path);
    let drive = parts.next().is_some_and(|d| {
        let b = d.as_bytes();
        b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    });
    drive && parts.all(|s| s != "." && s != "..")
}

fn map(raw: Raw) -> Result<(Pending, ManifestStats), ManifestError> {
    let mut stats = raw.stats;
    let view = raw
        .architecture
        .as_deref()
        .map_or(View::Native, View::of_architecture);
    stats.architecture = raw.architecture;
    stats.public_key_token = raw.token;
    stats.view = view;
    let mut pending = Pending::default();

    for key in raw.keys {
        let Some(key) = key else {
            stats.skipped.incomplete += 1;
            continue;
        };
        let skip_values = |stats: &mut ManifestStats, n: usize| {
            stats.skipped.values_of_skipped_keys += u64::try_from(n).unwrap_or(u64::MAX);
        };
        let expanded = match macros::expand(&key.name, view) {
            Ok(e) => e,
            Err(unknown) => {
                stats.skipped.key_unknown_macro += 1;
                stats.note_unknown(unknown.name);
                skip_values(&mut stats, key.values.len());
                continue;
            }
        };
        let forms = match key_forms(&expanded, view) {
            Ok(forms) => forms,
            Err(reason) => {
                *match reason {
                    KeySkip::UnknownRoot => &mut stats.skipped.unknown_root,
                    KeySkip::RootOnly => &mut stats.skipped.incomplete,
                    KeySkip::TooLong => &mut stats.skipped.too_long,
                } += 1;
                skip_values(&mut stats, key.values.len());
                continue;
            }
        };

        // Duplicates are left to `Records`, which keeps each record once.
        let mut values = Vec::with_capacity(key.values.len());
        for value in key.values {
            let ty = match value.ty.as_deref().and_then(value_type) {
                Some(ty) => ty,
                None => {
                    stats.unknown_value_types += 1;
                    0
                }
            };
            match macros::expand(&value.name, view) {
                Ok(names) => {
                    for name in names {
                        if name.len() > MAX_VALUE_NAME_BYTES {
                            stats.skipped.too_long += 1;
                        } else {
                            values.push((name, ty));
                        }
                    }
                }
                Err(unknown) => {
                    stats.skipped.value_unknown_macro += 1;
                    stats.note_unknown(unknown.name);
                }
            }
        }
        for form in &forms {
            pending.charge(form, segments_of_key(form).count())?;
            for (name, _) in &values {
                pending.charge(name, 1)?;
            }
        }
        pending.keys.push(PendingKey { forms, values });
    }

    for path in raw.paths {
        let expanded = match macros::expand(&path.text, view) {
            Ok(e) => e,
            Err(unknown) => {
                stats.skipped.path_unknown_macro += 1;
                stats.note_unknown(unknown.name);
                continue;
            }
        };
        let mut ok = Vec::with_capacity(expanded.len());
        let mut why = None;
        for text in expanded {
            let n = segments(&text).count();
            why = if !is_absolute(&text) {
                Some(&mut stats.skipped.not_absolute)
            } else if text.len() > MAX_PATH_BYTES || n > MAX_SEGMENTS {
                Some(&mut stats.skipped.too_long)
            } else if n < 2 {
                Some(&mut stats.skipped.incomplete)
            } else {
                ok.push((text, n));
                continue;
            };
            break;
        }
        if let Some(counter) = why {
            *counter += 1;
            continue;
        }
        for (text, n) in ok {
            pending.charge(&text, n)?;
            match path.kind {
                PathKind::Dir => pending.dirs.push(text),
                PathKind::File => pending.files.push(text),
            }
        }
    }
    Ok((pending, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(xml: &str) -> (Records, ManifestStats) {
        let mut r = Records::new();
        let stats = parse(xml.as_bytes(), &mut r).expect("parses");
        (r, stats)
    }

    fn manifest(arch: &str, body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
  <assemblyIdentity name="Test" version="1.0.0.0" processorArchitecture="{arch}" language="neutral" publicKeyToken="31bf3856ad364e35" versionScope="nonSxS"/>
  {body}
</assembly>"#
        )
    }

    #[test]
    fn identity_and_view() {
        let (_, s) = parse_str(&manifest("wow64", ""));
        assert_eq!(s.architecture.as_deref(), Some("wow64"));
        assert_eq!(s.public_key_token.as_deref(), Some("31bf3856ad364e35"));
        assert_eq!(s.view, View::Wow64);
        let (_, s) = parse_str(&manifest("amd64", ""));
        assert_eq!(s.view, View::Native);
        // A dependency's identity is another component's.
        let (_, s) = parse_str(
            r#"<assembly><dependency><dependentAssembly><assemblyIdentity processorArchitecture="x86" publicKeyToken="aa"/></dependentAssembly></dependency><assemblyIdentity processorArchitecture="amd64"/></assembly>"#,
        );
        assert_eq!(s.architecture.as_deref(), Some("amd64"));
        assert_eq!(s.public_key_token, None);
        assert_eq!(s.view, View::Native);
    }

    #[test]
    fn roots() {
        let (r, s) = parse_str(&manifest(
            "amd64",
            r#"<registryKeys>
                 <registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\A"/>
                 <registryKey keyName="HKLM\SOFTWARE\B\"/>
                 <registryKey keyName="HKEY_CLASSES_ROOT\.abc"/>
                 <registryKey keyName="HKEY_CLASSES_ROOT"/>
                 <registryKey keyName="HKEY_CURRENT_USER\Software\C"/>
                 <registryKey keyName="HKEY_USERS\.DEFAULT\D"/>
                 <registryKey keyName="HKEY_CURRENT_CONFIG\System"/>
                 <registryKey keyName="HKEY_LOCAL_MACHINE"/>
                 <registryKey keyName=""/>
                 <registryKey/>
               </registryKeys>"#,
        ));
        assert!(r.contains_key(r"HKLM\SOFTWARE\A"));
        assert!(r.contains_key(r"HKLM\SOFTWARE\B"));
        assert!(r.contains_key(r"HKLM\SOFTWARE\Classes\.abc"));
        assert!(r.contains_key(r"HKLM\SOFTWARE\Classes"));
        assert!(r.contains_key(r"HKU\S-1-5-21-0-0-0-1000\Software\C"));
        assert!(r.contains_key(r"HKU\.DEFAULT\Software\C"));
        assert!(r.contains_key(r"HKU\.DEFAULT\D"));
        assert_eq!(s.registry_keys, 10);
        assert_eq!(s.skipped.unknown_root, 1);
        assert_eq!(s.skipped.incomplete, 3, "root only, empty, no keyName");
        assert!(!r.keys().any(|k| k.starts_with("hkey_")));
    }

    #[test]
    fn wow64_twins() {
        let body = r#"<registryKey keyName="HKEY_CLASSES_ROOT\CLSID\{A}"><registryValue name="" valueType="REG_SZ" value="x"/></registryKey>
                      <registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\X"/>
                      <registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Y"/>
                      <registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Wow6432Node\Z"/>
                      <registryKey keyName="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\S"/>
                      <registryKey keyName="HKEY_CURRENT_USER\Software\U"/>"#;
        let (r, _) = parse_str(&manifest("wow64", body));
        assert!(r.contains_key(r"HKLM\SOFTWARE\Classes\CLSID\{A}"));
        assert!(r.contains_key(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}"));
        assert!(r.contains_value(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}", ""));
        assert!(r.contains_key(r"HKLM\SOFTWARE\Microsoft\X"));
        assert!(r.contains_key(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\X"));
        assert!(r.contains_key(r"HKLM\SOFTWARE\Wow6432Node\Y"));
        assert!(!r.keys().any(|k| k.contains(r"wow6432node\wow6432node")));
        assert!(!r.contains_key(r"HKLM\SOFTWARE\Classes\WOW6432Node\Wow6432Node\Z"));
        assert!(!r.contains_key(r"HKLM\SOFTWARE\WOW6432Node\Classes\Wow6432Node\Z"));
        assert!(
            !r.keys()
                .any(|k| k.starts_with(r"hklm\system") && k.contains("wow6432node"))
        );
        assert!(
            !r.keys()
                .any(|k| k.starts_with("hku") && k.contains("wow6432node"))
        );
        // The same keys in a native manifest have no twin: only the 32-bit keys written as such.
        let (n, _) = parse_str(&manifest("amd64", body));
        for k in n.keys().filter(|k| k.contains("wow6432node")) {
            assert!(
                k.ends_with("wow6432node")
                    || k.ends_with(r"wow6432node\y")
                    || k.ends_with(r"wow6432node\z"),
                "{k}"
            );
        }
        assert!(!n.contains_key(r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A}"));
    }

    #[test]
    fn value_types() {
        assert_eq!(value_type("REG_SZ"), Some(1));
        assert_eq!(value_type("reg_expand_sz"), Some(2));
        assert_eq!(value_type("REG_QWORD"), Some(11));
        assert_eq!(value_type("REG_MULTI_SZ"), Some(7));
        assert_eq!(value_type("REG_FOO"), None);
        let (r, s) = parse_str(&manifest(
            "amd64",
            r#"<registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\T">
                 <registryValue name="a" valueType="REG_DWORD" value="1"/>
                 <registryValue name="b" valueType="REG_WEIRD"/>
                 <registryValue valueType="REG_SZ"/>
               </registryKey>
               <registryValue name="orphan" valueType="REG_SZ"/>"#,
        ));
        let values: Vec<(&str, &str, u32)> =
            r.values().map(|v| (v.key(), v.name(), v.ty())).collect();
        assert_eq!(
            values,
            [
                (r"hklm\software\t", "", 1),
                (r"hklm\software\t", "a", 4),
                (r"hklm\software\t", "b", 0),
            ]
        );
        assert_eq!(s.unknown_value_types, 1);
        assert_eq!(s.skipped.orphan_values, 1);
        assert_eq!(s.registry_values, 4);
    }

    #[test]
    fn limits_skip_or_refuse() {
        let long = "A".repeat(MAX_KEY_BYTES);
        let (r, s) = parse_str(&manifest(
            "amd64",
            &format!(
                r#"<registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\{long}"><registryValue name="v"/></registryKey>
                   <registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\{deep}"/>
                   <file name="x" destinationPath="C:\{long}{long}"/>"#,
                deep = "a\\".repeat(MAX_SEGMENTS)
            ),
        ));
        assert_eq!(s.skipped.too_long, 3);
        assert_eq!(s.skipped.values_of_skipped_keys, 1);
        assert!(r.is_empty());

        let mut records = Records::new();
        let huge = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert_eq!(
            parse(&huge, &mut records),
            Err(ManifestError::TooLarge {
                bytes: MAX_MANIFEST_BYTES + 1
            })
        );
        let deep = format!(
            "{}{}",
            "<a>".repeat(MAX_DEPTH + 1),
            "</a>".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(
            parse(deep.as_bytes(), &mut records),
            Err(ManifestError::TooDeep)
        );
        let ok = format!("{}{}", "<a>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(parse(ok.as_bytes(), &mut records).is_ok());
        assert!(records.is_empty());
    }

    #[test]
    fn budget_refuses_amplification() {
        // Deep, long, distinct keys: each costs length times depth.
        let segment = "x".repeat(30);
        let key = vec![segment.as_str(); 60].join("\\");
        let mut body = String::new();
        for i in 0..200 {
            body.push_str(&format!(r#"<registryKey keyName="HKCU\{i}\{key}"/>"#));
        }
        let xml = manifest("amd64", &body);
        let mut r = Records::new();
        // 200 keys x 2 forms x ~1.9 KB x 63 segments = ~48 MB: within the budget.
        assert!(parse(xml.as_bytes(), &mut r).is_ok());
        let body = body.repeat(30);
        let xml = manifest("amd64", &body);
        let mut fresh = Records::new();
        assert_eq!(
            parse(xml.as_bytes(), &mut fresh),
            Err(ManifestError::TooMuchOutput)
        );
        assert!(fresh.is_empty());
    }

    #[test]
    fn encodings() {
        let xml = manifest("amd64", r#"<registryKey keyName="HKLM\SOFTWARE\Ü"/>"#);
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(xml.as_bytes());
        let mut le = vec![0xFF, 0xFE];
        le.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let mut be = vec![0xFE, 0xFF];
        be.extend(xml.encode_utf16().flat_map(u16::to_be_bytes));
        for bytes in [bom, le, be] {
            let mut r = Records::new();
            parse(&bytes, &mut r).expect("decodes");
            assert!(r.contains_key(r"HKLM\SOFTWARE\ü"));
        }
        let mut r = Records::new();
        assert_eq!(
            parse(&[0xFF, 0xFE, 0x41], &mut r),
            Err(ManifestError::Encoding)
        );
        assert_eq!(
            parse(&[0xFF, 0xFE, 0x00, 0xD8], &mut r),
            Err(ManifestError::Encoding)
        );
        assert_eq!(parse(b"<a>\xff</a>", &mut r), Err(ManifestError::Encoding));
    }

    #[test]
    fn document_shape_errors() {
        let mut r = Records::new();
        for (xml, want) in [
            ("", ManifestError::NoRoot),
            ("   ", ManifestError::NoRoot),
            ("<?xml version=\"1.0\"?>", ManifestError::NoRoot),
            ("<a>", ManifestError::Unbalanced),
            ("<a/><b/>", ManifestError::Unbalanced),
            ("<a></a>text", ManifestError::Unbalanced),
        ] {
            assert_eq!(parse(xml.as_bytes(), &mut r), Err(want), "{xml:?}");
        }
        for xml in [
            "<a></b>",
            "</a>",
            "<a x=\"1\" x=\"2\"/>",
            "<a x=1/>",
            "<a x=\"&nope;\"/>",
            "<a x=\"&#xD800;\"/>",
            "<a",
            "<a><!-- x </a>",
        ] {
            assert!(
                matches!(
                    parse(xml.as_bytes(), &mut r),
                    Err(ManifestError::Xml { .. } | ManifestError::Unbalanced)
                ),
                "{xml:?}"
            );
        }
        assert!(r.is_empty());
    }

    #[test]
    fn attribute_values_are_unescaped() {
        let (r, _) = parse_str(&manifest(
            "amd64",
            r#"<registryKey keyName="HKLM\SOFTWARE\A&amp;B&#x20;C"><registryValue name="&quot;q&quot;" valueType="REG_SZ"/></registryKey>"#,
        ));
        assert!(r.contains_key(r"HKLM\SOFTWARE\A&B C"));
        assert!(r.contains_value(r"HKLM\SOFTWARE\A&B C", "\"q\""));
    }
}
