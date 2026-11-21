//! The local baseline file: format, writer and reader (BASELINE_LOCAL_DESIGN.md §3.4, §3.5).
//!
//! # Format
//!
//! gzip of UTF-8 text with LF line ends:
//!
//! ```text
//! #purge-baseline-local 1\t<iso time>\t<computer>\t<edition>\t<build.ubr>\t<builder version>\t<source id>
//! #src\t<S1|S2|S3|S4|S5>\t<ok|incomplete|failed>\t<items read>\t<records>\t<skipped>\t<detail>
//! …one #src line per source, in source order…
//! K\t… V\t… D\t… F\t…          (the records of kb/baselines/README.md, sorted; V hash 0000000000000000)
//! #end\t<record count>\t<sha-256 hex of every byte before this line>
//! ```
//!
//! The `<detail>` field is a list of `name=value` entries separated by `; `, escaped like a record field.
//! An entry named `why` is one reason the source is not complete; the others are counts and facts for
//! the measurement. Nothing in the body is a time: two builds over the same inputs differ only in the
//! header's time and computer (which the builder takes from its caller).
//!
//! # Reader
//!
//! [`LocalBaseline::from_bytes`] accepts only this header ([`LOCAL_HEADER_TAG`], format
//! [`LOCAL_FORMAT_VERSION`], builder [`super::BUILDER_VERSION`]); the shipped header
//! `#purge-baseline 1` is refused, and the exact loader [`Baseline::from_bytes`] refuses this one (L6).
//! The records go into the same hashed sets as a shipped baseline ([`Baseline`], through the shared
//! record parser), but they are reachable only through [`LocalBaseline`]'s membership queries: a
//! `LocalBaseline` is never a `Baseline` and has no value data to restore (§3.3).
//!
//! A file larger than [`MAX_FILE_BYTES`], whose text exceeds [`MAX_TEXT_BYTES`], without a `#end` line,
//! with anything after it, with a record count or hash that does not match, or written by another
//! builder version is a **miss**: an error, never partial data.

use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::Records;
use super::records::escape_into;
use crate::baseline::{Baseline, BaselineError, PathKind, RecordCounts, RecordParser};

/// The first field of a local baseline's header.
pub const LOCAL_HEADER_TAG: &str = "#purge-baseline-local";
/// The only local format version this reader reads.
pub const LOCAL_FORMAT_VERSION: u32 = 1;
/// The tag of a source line.
pub const SRC_TAG: &str = "#src";
/// The tag of the trailer line.
pub const END_TAG: &str = "#end";
/// The largest local baseline file read (compressed, as stored): 64 MiB.
pub const MAX_FILE_BYTES: usize = 64 << 20;
/// The largest decompressed text read: 1 GiB (a host's file is a few hundred MB of text at most).
pub const MAX_TEXT_BYTES: u64 = 1 << 30;

/// The file name of a local baseline: `local-<EditionID>-<build>.<ubr>-<id>.tsv.gz` (design §3.5). It
/// never has the shape of a shipped baseline's name (`<EditionID>-<build>.<ubr>.tsv.gz`).
pub fn local_file_name(edition: &str, build: u32, ubr: u32, source_id: &str) -> String {
    format!("local-{edition}-{build}.{ubr}-{source_id}.tsv.gz")
}

/// One source of the local baseline (design §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LocalSource {
    /// Component manifests.
    S1,
    /// The default profile's hive.
    S2,
    /// `HKU\.DEFAULT`.
    S3,
    /// Inbox package manifests.
    S4,
    /// INF files (not built; design §3.1 "S5 is built only if the measurement shows a need").
    S5,
}

impl LocalSource {
    /// The sources a complete build has, in file order.
    pub const REQUIRED: [LocalSource; 4] = [
        LocalSource::S1,
        LocalSource::S2,
        LocalSource::S3,
        LocalSource::S4,
    ];

    /// `S1` … `S5`.
    pub fn tag(self) -> &'static str {
        match self {
            LocalSource::S1 => "S1",
            LocalSource::S2 => "S2",
            LocalSource::S3 => "S3",
            LocalSource::S4 => "S4",
            LocalSource::S5 => "S5",
        }
    }

    fn parse(tag: &str) -> Option<LocalSource> {
        [
            LocalSource::S1,
            LocalSource::S2,
            LocalSource::S3,
            LocalSource::S4,
            LocalSource::S5,
        ]
        .into_iter()
        .find(|s| s.tag() == tag)
    }
}

impl fmt::Display for LocalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// What the completeness seal says about one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceStatus {
    /// Read and above every floor.
    Ok,
    /// Read, but below a floor or not read whole (the reasons say which).
    Incomplete,
    /// Could not be read at all.
    Failed,
}

impl SourceStatus {
    /// `ok`, `incomplete` or `failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceStatus::Ok => "ok",
            SourceStatus::Incomplete => "incomplete",
            SourceStatus::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<SourceStatus> {
        match text {
            "ok" => Some(SourceStatus::Ok),
            "incomplete" => Some(SourceStatus::Incomplete),
            "failed" => Some(SourceStatus::Failed),
            _ => None,
        }
    }
}

/// One `#src` line: a source's status, counts and the reasons it is not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLine {
    /// Which source.
    pub source: LocalSource,
    /// What the seal says.
    pub status: SourceStatus,
    /// Items read: manifests listed (S1), keys and values walked (S2, S3), inbox packages (S4).
    pub items: u64,
    /// Distinct records the source gave on its own (`K`+`V`+`D`+`F`).
    pub records: u64,
    /// Items not used: manifests not expanded or not parsed (S1), keys not read whole (S2, S3),
    /// manifests not read or not parsed (S4).
    pub skipped: u64,
    /// Why the source is not complete (empty when it is).
    pub reasons: Vec<String>,
    /// Counts and facts for the measurement, as `(name, value)`.
    pub facts: Vec<(String, String)>,
}

impl SourceLine {
    /// The value of a fact, if the line has it.
    pub fn fact(&self, name: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The `<detail>` field, unescaped: `why=` entries first, then the facts, joined by `; `.
    pub fn detail(&self) -> String {
        let mut parts: Vec<String> = self.reasons.iter().map(|r| format!("why={r}")).collect();
        parts.extend(self.facts.iter().map(|(n, v)| format!("{n}={v}")));
        parts.join("; ")
    }

    /// The `#src` line without its line end.
    pub fn line(&self) -> String {
        let mut out = format!(
            "{SRC_TAG}\t{}\t{}\t{}\t{}\t{}\t",
            self.source.tag(),
            self.status.as_str(),
            self.items,
            self.records,
            self.skipped
        );
        escape_into(&self.detail(), &mut out);
        out
    }

    fn parse(line: &str) -> Option<SourceLine> {
        let fields: Vec<&str> = line.split('\t').collect();
        let [tag, source, status, items, records, skipped, detail] = fields.as_slice() else {
            return None;
        };
        if *tag != SRC_TAG {
            return None;
        }
        let detail = unescape(detail)?;
        let mut reasons = Vec::new();
        let mut facts = Vec::new();
        for entry in detail.split("; ").filter(|e| !e.is_empty()) {
            let (name, value) = entry.split_once('=')?;
            if name == "why" {
                reasons.push(value.to_owned());
            } else {
                facts.push((name.to_owned(), value.to_owned()));
            }
        }
        Some(SourceLine {
            source: LocalSource::parse(source)?,
            status: SourceStatus::parse(status)?,
            items: items.parse().ok()?,
            records: records.parse().ok()?,
            skipped: skipped.parse().ok()?,
            reasons,
            facts,
        })
    }
}

/// A detail value as the format can carry it: `;` (the entry separator) becomes `,`, control
/// characters become spaces.
pub fn fact_value(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            ';' => ',',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

/// A header field as the format can carry it: TAB, line ends and other control characters become `_`.
fn header_field(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

/// The header of a local baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHeader {
    /// When it was built (ISO-8601 UTC).
    pub built_at: String,
    /// The machine it was built on.
    pub computer: String,
    /// Windows `EditionID`.
    pub edition: String,
    /// Build number.
    pub build: u32,
    /// Update build revision.
    pub ubr: u32,
    /// The builder's version ([`super::BUILDER_VERSION`] when written by this one).
    pub builder_version: String,
    /// The source id (`super::SourceStamp::id`).
    pub source_id: String,
}

impl LocalHeader {
    /// The header line without its line end.
    pub fn line(&self) -> String {
        format!(
            "{LOCAL_HEADER_TAG} {LOCAL_FORMAT_VERSION}\t{}\t{}\t{}\t{}.{}\t{}\t{}",
            header_field(&self.built_at),
            header_field(&self.computer),
            header_field(&self.edition),
            self.build,
            self.ubr,
            header_field(&self.builder_version),
            header_field(&self.source_id),
        )
    }

    fn parse(line: &str) -> Result<LocalHeader, LocalBaselineError> {
        let bad = || LocalBaselineError::BadHeader(line.chars().take(200).collect());
        let fields: Vec<&str> = line.split('\t').collect();
        let (tag, version) = fields
            .first()
            .and_then(|f| f.split_once(' '))
            .ok_or_else(bad)?;
        if tag != LOCAL_HEADER_TAG {
            return Err(bad());
        }
        if version.trim().parse::<u32>().ok() != Some(LOCAL_FORMAT_VERSION) {
            return Err(LocalBaselineError::UnsupportedVersion(version.to_owned()));
        }
        let [_, built_at, computer, edition, os, builder, id] = fields.as_slice() else {
            return Err(bad());
        };
        let (build, ubr) = os.split_once('.').ok_or_else(bad)?;
        Ok(LocalHeader {
            built_at: (*built_at).to_owned(),
            computer: (*computer).to_owned(),
            edition: (*edition).to_owned(),
            build: build.parse().map_err(|_| bad())?,
            ubr: ubr.parse().map_err(|_| bad())?,
            builder_version: (*builder).to_owned(),
            source_id: (*id).to_owned(),
        })
    }
}

/// An encoded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// The gzip bytes.
    pub bytes: Vec<u8>,
    /// Record lines written (`K`+`V`+`D`+`F`).
    pub record_count: u64,
    /// The SHA-256 of the text before `#end`, lower-case hex.
    pub sha256: String,
    /// Bytes of text before `#end`.
    pub text_bytes: u64,
}

/// Writes through to `inner`, hashing and counting every byte.
struct HashingWriter<W> {
    inner: W,
    sha: Sha256,
    bytes: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.sha.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Encodes a local baseline: header, the `#src` lines in the order given, the sorted records, the
/// `#end` line; gzip (fixed header, no time or name in it), so equal inputs give equal bytes.
pub fn encode(
    header: &LocalHeader,
    sources: &[SourceLine],
    records: &Records,
) -> io::Result<Encoded> {
    let gz = flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
    let mut w = HashingWriter {
        inner: io::BufWriter::with_capacity(1 << 20, gz),
        sha: Sha256::new(),
        bytes: 0,
    };
    w.write_all(header.line().as_bytes())?;
    w.write_all(b"\n")?;
    for s in sources {
        w.write_all(s.line().as_bytes())?;
        w.write_all(b"\n")?;
    }
    records.write_records(&mut w)?;
    let c = records.counts();
    let record_count = c.keys + c.values + c.dirs + c.files;
    let sha256 = hex(&w.sha.finalize_reset());
    let text_bytes = w.bytes;
    let mut gz = w.inner.into_inner().map_err(|e| e.into_error())?;
    writeln!(gz, "{END_TAG}\t{record_count}\t{sha256}")?;
    Ok(Encoded {
        bytes: gz.finish()?,
        record_count,
        sha256,
        text_bytes,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Undoes the record escapes (`\\`, `\t`, `\n`, `\r`, `\0`); `None` on an unknown escape.
fn unescape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            '\\' => '\\',
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            '0' => '\0',
            _ => return None,
        });
    }
    Some(out)
}

/// Why a local baseline file is a miss.
#[derive(Debug)]
pub enum LocalBaselineError {
    /// The file could not be read or decompressed (a truncated gzip stream ends here).
    Io(io::Error),
    /// Larger than [`MAX_FILE_BYTES`], or its text larger than [`MAX_TEXT_BYTES`].
    TooLarge,
    /// The first line is not a `#purge-baseline-local` header with seven fields (a shipped
    /// baseline's `#purge-baseline` header included).
    BadHeader(String),
    /// The header names a format version other than [`LOCAL_FORMAT_VERSION`].
    UnsupportedVersion(String),
    /// Written by another builder version.
    BuilderVersion {
        /// The version in the file.
        found: String,
    },
    /// A `#src` line could not be parsed.
    BadSource {
        /// 1-based line number.
        line: u64,
    },
    /// A record line could not be parsed.
    BadRecord(BaselineError),
    /// No `#end` line (a truncated file).
    NoEnd,
    /// The `#end` line is malformed.
    BadEnd {
        /// 1-based line number.
        line: u64,
    },
    /// The `#end` line names another record count.
    CountMismatch {
        /// What `#end` says.
        expected: u64,
        /// Record lines read.
        found: u64,
    },
    /// The `#end` line names another hash.
    HashMismatch,
    /// Something follows the `#end` line.
    AfterEnd,
}

impl fmt::Display for LocalBaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the local baseline: {e}"),
            Self::TooLarge => write!(
                f,
                "the local baseline is larger than {MAX_FILE_BYTES} bytes, or its text than {MAX_TEXT_BYTES}"
            ),
            Self::BadHeader(h) => write!(f, "not a local baseline header: {h:?}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "local baseline format version {v:?} is not supported")
            }
            Self::BuilderVersion { found } => write!(
                f,
                "the local baseline was written by builder {found:?}, this one is {:?}",
                super::BUILDER_VERSION
            ),
            Self::BadSource { line } => write!(f, "local baseline line {line}: bad #src line"),
            Self::BadRecord(e) => write!(f, "local baseline: {e}"),
            Self::NoEnd => write!(f, "the local baseline has no #end line (truncated)"),
            Self::BadEnd { line } => write!(f, "local baseline line {line}: bad #end line"),
            Self::CountMismatch { expected, found } => write!(
                f,
                "the local baseline's #end names {expected} records, the file has {found}"
            ),
            Self::HashMismatch => write!(f, "the local baseline's #end hash does not match"),
            Self::AfterEnd => write!(f, "the local baseline has lines after #end"),
        }
    }
}

impl std::error::Error for LocalBaselineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::BadRecord(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for LocalBaselineError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// A local baseline as read from its file: header, source lines and the hashed record sets. See the
/// module documentation.
#[derive(Debug, Clone)]
pub struct LocalBaseline {
    header: LocalHeader,
    sources: Vec<SourceLine>,
    record_count: u64,
    sets: Baseline,
}

impl LocalBaseline {
    /// Loads a local baseline file of at most [`MAX_FILE_BYTES`].
    pub fn load(path: &Path) -> Result<LocalBaseline, LocalBaselineError> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Parses a local baseline from memory: gzip (recognised by its magic number) or the plain text.
    pub fn from_bytes(bytes: &[u8]) -> Result<LocalBaseline, LocalBaselineError> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(LocalBaselineError::TooLarge);
        }
        if bytes.starts_with(&[0x1f, 0x8b]) {
            let gz = flate2::bufread::MultiGzDecoder::new(bytes);
            Self::from_reader(BufReader::with_capacity(1 << 18, gz))
        } else {
            Self::from_reader(bytes)
        }
    }

    /// Parses the plain (already decompressed) text of a local baseline.
    pub fn from_reader<R: BufRead>(reader: R) -> Result<LocalBaseline, LocalBaselineError> {
        let mut reader = reader.take(MAX_TEXT_BYTES + 1);
        let mut raw: Vec<u8> = Vec::with_capacity(512);
        let mut sha = Sha256::new();
        let mut total: u64 = 0;
        let mut line_no: u64 = 0;
        let mut header: Option<LocalHeader> = None;
        let mut sets: Option<Baseline> = None;
        let mut sources = Vec::new();
        let mut parser = RecordParser::new();
        let mut records: u64 = 0;
        let mut ended = false;
        loop {
            raw.clear();
            let n = reader.read_until(b'\n', &mut raw)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_TEXT_BYTES {
                return Err(LocalBaselineError::TooLarge);
            }
            line_no += 1;
            if ended {
                return Err(LocalBaselineError::AfterEnd);
            }
            // Every line, the last one included, ends with LF; a line without one is a truncation.
            let Some(line) = raw.strip_suffix(b"\n") else {
                return Err(if raw.starts_with(END_TAG.as_bytes()) {
                    LocalBaselineError::BadEnd { line: line_no }
                } else {
                    LocalBaselineError::NoEnd
                });
            };
            if line_no == 1 {
                let text = String::from_utf8_lossy(line);
                let h = LocalHeader::parse(&text)?;
                if h.builder_version != super::BUILDER_VERSION {
                    return Err(LocalBaselineError::BuilderVersion {
                        found: h.builder_version,
                    });
                }
                sets = Some(Baseline::empty(
                    &h.edition,
                    h.build,
                    h.ubr,
                    &h.built_at,
                    &h.computer,
                    "local",
                ));
                header = Some(h);
                sha.update(&raw);
                continue;
            }
            if let Some(rest) = line.strip_prefix(END_TAG.as_bytes()) {
                let bad = LocalBaselineError::BadEnd { line: line_no };
                let text = std::str::from_utf8(rest).map_err(|_| bad)?;
                let mut fields = text.split('\t');
                let (Some(""), Some(count), Some(hash), None) =
                    (fields.next(), fields.next(), fields.next(), fields.next())
                else {
                    return Err(LocalBaselineError::BadEnd { line: line_no });
                };
                let expected: u64 = count
                    .parse()
                    .map_err(|_| LocalBaselineError::BadEnd { line: line_no })?;
                if expected != records {
                    return Err(LocalBaselineError::CountMismatch {
                        expected,
                        found: records,
                    });
                }
                if hash != hex(&sha.finalize_reset()) {
                    return Err(LocalBaselineError::HashMismatch);
                }
                ended = true;
                continue;
            }
            sha.update(&raw);
            if line.is_empty() {
                continue;
            }
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line[0] == b'#' {
                if line.starts_with(b"#src\t") {
                    let text = std::str::from_utf8(line)
                        .map_err(|_| LocalBaselineError::BadSource { line: line_no })?;
                    sources.push(
                        SourceLine::parse(text)
                            .ok_or(LocalBaselineError::BadSource { line: line_no })?,
                    );
                }
                continue;
            }
            let out = sets
                .as_mut()
                .ok_or_else(|| LocalBaselineError::BadHeader(String::new()))?;
            parser
                .add(out, line, line_no)
                .map_err(LocalBaselineError::BadRecord)?;
            records += 1;
        }
        let (Some(header), Some(mut sets)) = (header, sets) else {
            return Err(LocalBaselineError::BadHeader(String::new()));
        };
        if !ended {
            return Err(LocalBaselineError::NoEnd);
        }
        sets.finish_sets();
        Ok(LocalBaseline {
            header,
            sources,
            record_count: records,
            sets,
        })
    }

    /// The header.
    pub fn header(&self) -> &LocalHeader {
        &self.header
    }

    /// The source id the file was built for.
    pub fn id(&self) -> &str {
        &self.header.source_id
    }

    /// The `#src` lines, in file order.
    pub fn sources(&self) -> &[SourceLine] {
        &self.sources
    }

    /// The completeness seal (design §3.4, L2): every source S1 to S4 has exactly one `#src` line and
    /// each says `ok`. An incomplete local baseline is for presence only.
    pub fn complete(&self) -> bool {
        seal_reasons(&self.sources).is_empty()
    }

    /// Why the build is not complete, one line per source (empty when [`LocalBaseline::complete`]).
    pub fn incomplete_reasons(&self) -> Vec<String> {
        seal_reasons(&self.sources)
    }

    /// Record lines in the file.
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Records of each type in the file.
    pub fn counts(&self) -> RecordCounts {
        self.sets.counts()
    }

    /// Whether this Windows says it has this registry key ([`Baseline::has_key`] rules).
    pub fn has_key(&self, key: &str) -> bool {
        self.sets.has_key(key)
    }

    /// [`Baseline::has_key_exact_view`] over the local records.
    pub fn has_key_exact_view(&self, key: &str) -> bool {
        self.sets.has_key_exact_view(key)
    }

    /// Whether a value of this name is recorded in this key (names only; there is no data, §3.3).
    pub fn has_value(&self, key: &str, name: &str) -> bool {
        self.sets.has_value(key, name)
    }

    /// Whether this file or directory is recorded.
    pub fn has_path(&self, path: &str) -> bool {
        self.sets.has_path(path)
    }

    /// Whether this path is recorded, and as what.
    pub fn path_kind(&self, path: &str) -> Option<PathKind> {
        self.sets.path_kind(path)
    }

    /// [`Baseline::has_profile_path`] over the local records.
    pub fn has_profile_path(&self, profile_dir: &str, path: &str) -> bool {
        self.sets.has_profile_path(profile_dir, path)
    }

    /// [`Baseline::has_segment`] over the local records.
    pub fn has_segment(&self, name: &str) -> bool {
        self.sets.has_segment(name)
    }

    /// [`Baseline::has_token`] over the local records.
    pub fn has_token(&self, token: &str) -> bool {
        self.sets.has_token(token)
    }
}

/// The seal over a set of `#src` lines: one reason line per source that is missing, doubled or not
/// `ok`.
pub fn seal_reasons(sources: &[SourceLine]) -> Vec<String> {
    let mut out = Vec::new();
    for want in LocalSource::REQUIRED {
        let lines: Vec<&SourceLine> = sources.iter().filter(|s| s.source == want).collect();
        match lines.as_slice() {
            [] => out.push(format!("{want}: no #src line")),
            [one] if one.status == SourceStatus::Ok => {}
            [one] => {
                let why = if one.reasons.is_empty() {
                    "no reason given".to_owned()
                } else {
                    one.reasons.join("; ")
                };
                out.push(format!("{want} {}: {why}", one.status.as_str()));
            }
            _ => out.push(format!("{want}: more than one #src line")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> LocalHeader {
        LocalHeader {
            built_at: "2026-11-21T00:00:00Z".into(),
            computer: "PC".into(),
            edition: "Professional".into(),
            build: 26100,
            ubr: 9711,
            builder_version: super::super::BUILDER_VERSION.into(),
            source_id: "0123456789abcdef".into(),
        }
    }

    fn ok_line(source: LocalSource) -> SourceLine {
        SourceLine {
            source,
            status: SourceStatus::Ok,
            items: 1,
            records: 2,
            skipped: 0,
            reasons: Vec::new(),
            facts: vec![("keys".into(), "2".into())],
        }
    }

    fn sample() -> (Vec<SourceLine>, Records) {
        let mut r = Records::new();
        r.add_key(r"HKLM\SOFTWARE\Classes\CLSID\{A}");
        r.add_value(r"HKLM\SOFTWARE\Classes\.txt", "Content Type", 1);
        r.add_file(r"C:\Windows\System32\a.dll");
        let mut sources: Vec<SourceLine> = LocalSource::REQUIRED.map(ok_line).to_vec();
        sources[2].status = SourceStatus::Incomplete;
        sources[2].reasons = vec!["1 key vanished".into()];
        sources[2]
            .facts
            .push(("origin".into(), r"HKU\.DEFAULT".into()));
        (sources, r)
    }

    fn text_of(bytes: &[u8]) -> String {
        let mut s = String::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_string(&mut s)
            .unwrap();
        s
    }

    fn gz(text: &str) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(text.as_bytes()).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn round_trip_and_seal_reasons() {
        let (sources, records) = sample();
        let enc = encode(&header(), &sources, &records).unwrap();
        assert_eq!(enc.record_count, 9, "{}", text_of(&enc.bytes));
        let text = text_of(&enc.bytes);
        assert!(text.starts_with(
            "#purge-baseline-local 1\t2026-11-21T00:00:00Z\tPC\tProfessional\t26100.9711\tbl.1\t0123456789abcdef\n#src\tS1\tok\t1\t2\t0\tkeys=2\n"
        ));
        assert!(text.contains(
            "#src\tS3\tincomplete\t1\t2\t0\twhy=1 key vanished; keys=2; origin=HKU\\\\.DEFAULT\n"
        ));
        let end = text.lines().last().unwrap();
        assert_eq!(end, format!("#end\t9\t{}", enc.sha256));

        let lb = LocalBaseline::from_bytes(&enc.bytes).unwrap();
        assert_eq!(lb.header(), &header());
        assert_eq!(lb.id(), "0123456789abcdef");
        assert_eq!(lb.sources(), sources.as_slice());
        assert_eq!(lb.record_count(), 9);
        assert!(!lb.complete());
        assert_eq!(
            lb.incomplete_reasons(),
            ["S3 incomplete: 1 key vanished".to_owned()]
        );
        assert!(lb.has_key(r"HKCR\CLSID\{a}"));
        assert!(lb.has_value(r"HKLM\SOFTWARE\Classes\.txt", "content type"));
        assert!(lb.has_path(r"c:\windows\system32\A.DLL"));
        assert_eq!(lb.path_kind(r"C:\Windows\System32"), Some(PathKind::Dir));
        assert!(!lb.has_key(r"HKLM\SOFTWARE\Classes\CLSID\{B}"));
        assert!(lb.has_segment("{A}") && lb.has_token("A"));

        // The plain text reads the same.
        assert_eq!(
            LocalBaseline::from_bytes(text.as_bytes())
                .unwrap()
                .record_count(),
            9
        );
        // Same input, same bytes.
        assert_eq!(encode(&header(), &sources, &records).unwrap(), enc);
    }

    #[test]
    fn seal_needs_every_source_once_and_ok() {
        let all: Vec<SourceLine> = LocalSource::REQUIRED.map(ok_line).to_vec();
        assert!(seal_reasons(&all).is_empty());
        assert_eq!(seal_reasons(&all[1..]), ["S1: no #src line".to_owned()]);
        let mut doubled = all.clone();
        doubled.push(ok_line(LocalSource::S4));
        assert_eq!(
            seal_reasons(&doubled),
            ["S4: more than one #src line".to_owned()]
        );
        let mut failed = all.clone();
        failed[1].status = SourceStatus::Failed;
        assert_eq!(
            seal_reasons(&failed),
            ["S2 failed: no reason given".to_owned()]
        );
    }

    #[test]
    fn truncated_tampered_and_swapped_files_are_misses() {
        let (sources, records) = sample();
        let enc = encode(&header(), &sources, &records).unwrap();
        let text = text_of(&enc.bytes);

        // Truncated gzip stream.
        let cut = &enc.bytes[..enc.bytes.len() - 12];
        assert!(matches!(
            LocalBaseline::from_bytes(cut),
            Err(LocalBaselineError::Io(_))
        ));
        // Truncated text: no #end, or a cut #end line.
        let no_end = &text[..text.rfind("#end").unwrap()];
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(no_end)),
            Err(LocalBaselineError::NoEnd)
        ));
        let mid_record = &text[..text.find("K\t").unwrap() + 5];
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(mid_record)),
            Err(LocalBaselineError::NoEnd)
        ));
        let cut_end = text.trim_end_matches('\n');
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(cut_end)),
            Err(LocalBaselineError::BadEnd { .. })
        ));
        // A removed record line: the count no longer matches.
        let removed: String = text
            .lines()
            .filter(|l| !l.starts_with("F\t"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&removed)),
            Err(LocalBaselineError::CountMismatch {
                expected: 9,
                found: 8
            })
        ));
        // A changed record, or a changed #src line: the hash no longer matches.
        let changed = text.replacen("{a}", "{b}", 1);
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&changed)),
            Err(LocalBaselineError::HashMismatch)
        ));
        let promoted = text.replacen("S3\tincomplete", "S3\tok", 1);
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&promoted)),
            Err(LocalBaselineError::HashMismatch)
        ));
        // A wrong hash in #end.
        let wrong = text.replacen(&enc.sha256, &"0".repeat(64), 1);
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&wrong)),
            Err(LocalBaselineError::HashMismatch)
        ));
        // Anything after #end.
        let after = format!("{text}K\thklm\\\\software\\\\x\n");
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&after)),
            Err(LocalBaselineError::AfterEnd)
        ));
        // Another builder version.
        let other = text.replacen("\tbl.1\t", "\tbl.0\t", 1);
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&other)),
            Err(LocalBaselineError::BuilderVersion { .. })
        ));
        // Too large.
        assert!(matches!(
            LocalBaseline::from_bytes(&vec![b'#'; MAX_FILE_BYTES + 1]),
            Err(LocalBaselineError::TooLarge)
        ));

        // L6: the exact loader refuses the local header ...
        assert!(matches!(
            Baseline::from_bytes(&enc.bytes),
            Err(BaselineError::BadHeader(_))
        ));
        // ... and the local reader refuses the shipped one, even with a valid #end.
        let shipped_body = "#purge-baseline 1\t2026-11-21T00:00:00Z\tPC\tProfessional\t26100.9711\nK\thklm\\\\software\n";
        let mut sha = Sha256::new();
        sha.update(shipped_body.as_bytes());
        let shipped = format!("{shipped_body}#end\t1\t{}\n", hex(&sha.finalize()));
        assert!(Baseline::from_bytes(shipped.as_bytes()).is_ok());
        assert!(matches!(
            LocalBaseline::from_bytes(&gz(&shipped)),
            Err(LocalBaselineError::BadHeader(_))
        ));
        assert!(matches!(
            LocalBaseline::from_bytes(b"#purge-baseline-local 2\tT\tPC\tE\t1.2\tbl.1\tid\n"),
            Err(LocalBaselineError::UnsupportedVersion(_))
        ));
        assert!(matches!(
            LocalBaseline::from_bytes(b""),
            Err(LocalBaselineError::BadHeader(_))
        ));
    }

    #[test]
    fn names_and_detail_values() {
        assert_eq!(
            local_file_name("Professional", 26100, 9711, "0123456789abcdef"),
            "local-Professional-26100.9711-0123456789abcdef.tsv.gz"
        );
        assert_eq!(fact_value("a;b\tc"), "a,b c");
        let mut h = header();
        h.computer = "P\tC".into();
        assert!(h.line().contains("\tP_C\t"));
    }
}
