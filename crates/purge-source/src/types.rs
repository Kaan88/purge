//! Value types shared by every source (ENGINE_PLAN.md §3.2 `purge-source`).
//!
//! These are what the [`RegistrySource`](crate::registry::RegistrySource),
//! [`FileSystemSource`](crate::filesystem::FileSystemSource) and [`SystemSource`](crate::system::SystemSource)
//! traits hand to the scanners. They carry no behaviour that touches the machine: the `Live` implementation
//! fills them from `purge-win`, the `Fixture` from JSON or a rig snapshot.
//!
//! Two rules run through the whole module:
//! - **Unknown is not absent.** A source that cannot tell (access denied, a removable volume, a location
//!   the fixture did not capture) says so ([`ExistsState::Unknown`], [`SourceError::NotCaptured`],
//!   [`RegData::data_unknown`]), and consumers must not treat that as "gone".
//! - **Raw data stays raw.** Registry data is kept as type + bytes; the typed accessors decode on demand
//!   and return `None` when the type does not match or the bytes are not known.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use purge_model::{FileTime, MsiContext, OsInfo};

// ---------------------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------------------

/// Why a source could not answer a query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The key, value, file or directory does not exist.
    #[error("not found")]
    NotFound,
    /// The object exists (or may exist) but reading it was refused.
    #[error("access denied")]
    AccessDenied,
    /// The source holds no data for this location (a fixture that did not capture it). The real state is
    /// unknown; never treat this as [`SourceError::NotFound`].
    #[error("not captured by this source")]
    NotCaptured,
    /// The path is, or passes through, a reparse point, which sources never traverse.
    #[error("reparse point not traversed")]
    ReparsePoint,
    /// The object exists but is not the kind the call needs (a directory where a file is expected, a file
    /// that is not a shortcut, …).
    #[error("wrong kind of object")]
    WrongKind,
    /// The path is not in a form this source accepts.
    #[error("invalid path: {0}")]
    InvalidPath(String),
    /// Any other operating-system error, by its Win32 code.
    #[error("os error {0}")]
    Other(u32),
}

/// Result of a source query.
pub type SourceResult<T> = Result<T, SourceError>;

/// Helpers for the common "missing is fine" pattern.
pub trait SourceResultExt<T> {
    /// Turns [`SourceError::NotFound`] into `Ok(None)`; every other error stays an error.
    fn found(self) -> SourceResult<Option<T>>;
}

impl<T> SourceResultExt<T> for SourceResult<T> {
    fn found(self) -> SourceResult<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(SourceError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Whether a path exists, with an explicit "cannot tell".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExistsState {
    /// The object exists.
    Present,
    /// The object positively does not exist (e.g. `ERROR_FILE_NOT_FOUND` on a mounted fixed NTFS volume).
    Absent,
    /// The source cannot tell (access denied, removable or network volume, not captured, …). Dangling
    /// checks must treat this as "not dangling".
    Unknown,
}

impl ExistsState {
    /// `true` only for [`ExistsState::Absent`].
    pub fn is_absent(self) -> bool {
        self == ExistsState::Absent
    }

    /// `true` only for [`ExistsState::Present`].
    pub fn is_present(self) -> bool {
        self == ExistsState::Present
    }
}

// ---------------------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------------------

/// `REG_NONE`.
pub const REG_NONE: u32 = 0;
/// `REG_SZ`.
pub const REG_SZ: u32 = 1;
/// `REG_EXPAND_SZ`.
pub const REG_EXPAND_SZ: u32 = 2;
/// `REG_BINARY`.
pub const REG_BINARY: u32 = 3;
/// `REG_DWORD` (little endian).
pub const REG_DWORD: u32 = 4;
/// `REG_DWORD_BIG_ENDIAN`.
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
/// `REG_LINK` (the `SymbolicLinkValue` of a registry link).
pub const REG_LINK: u32 = 6;
/// `REG_MULTI_SZ`.
pub const REG_MULTI_SZ: u32 = 7;
/// `REG_QWORD` (little endian).
pub const REG_QWORD: u32 = 11;

/// How many leading bytes of a value [`RegData::binary_utf16_strings`] scans.
pub const BINARY_UTF16_SCAN_MAX: usize = 4096;
/// Shortest UTF-16 run (in characters) [`RegData::binary_utf16_strings`] reports.
pub const BINARY_UTF16_MIN_CHARS: usize = 4;

/// The data of one registry value: its type and raw bytes, plus what the source knows about their
/// completeness.
///
/// Built by the `Live` source from `RegEnumValueW` (always complete) or by a fixture. A rig snapshot only
/// keeps a text preview, so a fixture built from one may hold data that is cut short
/// ([`truncated`](Self::truncated)) or not known at all ([`data_unknown`](Self::data_unknown)).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegData {
    /// The registry type (`REG_*`); any `u32`, including undocumented ones.
    pub ty: u32,
    /// The raw data bytes, or the known prefix of them when [`truncated`](Self::truncated).
    pub bytes: Vec<u8>,
    /// Length of the full data in bytes as the source reported it. Equals `bytes.len()` for complete data.
    pub len: u32,
    /// A hash of the full data recorded by the source, when it has one (rig snapshots: the first 16 hex
    /// chars of SHA-256 as `u64`). `None` from the `Live` source.
    pub hash: Option<u64>,
    /// `bytes` holds only a prefix of the data (a rig preview cut at 1024 characters). Text accessors return
    /// that prefix; callers that need the whole value must not rely on it.
    pub truncated: bool,
    /// The bytes are not known at all (a rig snapshot keeps no preview for this type). Every accessor
    /// returns `None`.
    pub data_unknown: bool,
}

fn utf16_bytes(units: impl Iterator<Item = u16>) -> Vec<u8> {
    units.flat_map(u16::to_le_bytes).collect()
}

fn bytes_to_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn len_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl RegData {
    /// Complete data of any type.
    pub fn new(ty: u32, bytes: Vec<u8>) -> Self {
        let len = len_u32(bytes.len());
        Self {
            ty,
            bytes,
            len,
            hash: None,
            truncated: false,
            data_unknown: false,
        }
    }

    /// Data whose bytes are not known, only their type and length.
    pub fn unknown(ty: u32, len: u32) -> Self {
        Self {
            ty,
            bytes: Vec::new(),
            len,
            hash: None,
            truncated: false,
            data_unknown: true,
        }
    }

    fn string_bytes(s: &str, terminate: bool) -> Vec<u8> {
        let mut b = utf16_bytes(s.encode_utf16());
        if terminate {
            b.extend_from_slice(&[0, 0]);
        }
        b
    }

    /// `REG_SZ` data as Windows stores it: UTF-16LE with a terminating NUL.
    pub fn from_sz(s: &str) -> Self {
        Self::new(REG_SZ, Self::string_bytes(s, true))
    }

    /// `REG_EXPAND_SZ` data: UTF-16LE with a terminating NUL.
    pub fn from_expand_sz(s: &str) -> Self {
        Self::new(REG_EXPAND_SZ, Self::string_bytes(s, true))
    }

    /// `REG_LINK` data: the UTF-16LE target, without a terminator (as `SymbolicLinkValue` is stored).
    pub fn from_link(target: &str) -> Self {
        Self::new(REG_LINK, Self::string_bytes(target, false))
    }

    /// `REG_MULTI_SZ` data: each string NUL-terminated, then a final NUL.
    pub fn from_multi_sz<S: AsRef<str>>(segments: &[S]) -> Self {
        let mut b = Vec::new();
        for s in segments {
            b.extend(Self::string_bytes(s.as_ref(), true));
        }
        b.extend_from_slice(&[0, 0]);
        Self::new(REG_MULTI_SZ, b)
    }

    /// `REG_DWORD` data.
    pub fn from_dword(v: u32) -> Self {
        Self::new(REG_DWORD, v.to_le_bytes().to_vec())
    }

    /// `REG_QWORD` data.
    pub fn from_qword(v: u64) -> Self {
        Self::new(REG_QWORD, v.to_le_bytes().to_vec())
    }

    /// `REG_BINARY` data.
    pub fn from_binary(bytes: Vec<u8>) -> Self {
        Self::new(REG_BINARY, bytes)
    }

    /// Whether the full bytes are known (neither unknown nor truncated).
    pub fn is_complete(&self) -> bool {
        !self.data_unknown && !self.truncated
    }

    /// The bytes as UTF-16 text up to the first NUL, whatever the type; `None` when the data is unknown.
    fn text(&self) -> Option<String> {
        if self.data_unknown {
            return None;
        }
        let units = bytes_to_units(&self.bytes);
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        Some(String::from_utf16_lossy(&units[..end]))
    }

    /// Whether anything but NULs follows the first NUL of the data: text the string accessors
    /// ([`string`](Self::string), [`sz`](Self::sz)) do not return. `false` for unknown data.
    pub fn has_text_after_nul(&self) -> bool {
        let units = bytes_to_units(&self.bytes);
        units
            .iter()
            .position(|&c| c == 0)
            .is_some_and(|end| units[end..].iter().any(|&c| c != 0))
    }

    /// The string of a `REG_SZ` value (up to the first NUL).
    pub fn sz(&self) -> Option<String> {
        (self.ty == REG_SZ).then(|| self.text()).flatten()
    }

    /// The unexpanded string of a `REG_EXPAND_SZ` value (up to the first NUL).
    pub fn expand_sz(&self) -> Option<String> {
        (self.ty == REG_EXPAND_SZ).then(|| self.text()).flatten()
    }

    /// The string of a `REG_SZ` or `REG_EXPAND_SZ` value, unexpanded.
    pub fn string(&self) -> Option<String> {
        matches!(self.ty, REG_SZ | REG_EXPAND_SZ)
            .then(|| self.text())
            .flatten()
    }

    /// The target of a `REG_LINK` value.
    pub fn link_target(&self) -> Option<String> {
        (self.ty == REG_LINK).then(|| self.text()).flatten()
    }

    /// The segments of a `REG_MULTI_SZ` value.
    ///
    /// The data is split at every NUL and trailing empty strings (the terminators) are dropped; an empty
    /// string in the middle of the list is kept as a segment, so indexes match the raw data.
    pub fn multi_sz(&self) -> Option<Vec<String>> {
        if self.ty != REG_MULTI_SZ || self.data_unknown {
            return None;
        }
        let units = bytes_to_units(&self.bytes);
        let mut parts: Vec<String> = units
            .split(|&c| c == 0)
            .map(String::from_utf16_lossy)
            .collect();
        while parts.last().is_some_and(String::is_empty) {
            parts.pop();
        }
        Some(parts)
    }

    /// The number of a `REG_DWORD` (or `REG_DWORD_BIG_ENDIAN`) value with exactly four bytes.
    pub fn dword(&self) -> Option<u32> {
        if self.data_unknown || self.truncated {
            return None;
        }
        let arr: [u8; 4] = self.bytes.as_slice().try_into().ok()?;
        match self.ty {
            REG_DWORD => Some(u32::from_le_bytes(arr)),
            REG_DWORD_BIG_ENDIAN => Some(u32::from_be_bytes(arr)),
            _ => None,
        }
    }

    /// The number of a `REG_QWORD` value with exactly eight bytes.
    pub fn qword(&self) -> Option<u64> {
        if self.ty != REG_QWORD || self.data_unknown || self.truncated {
            return None;
        }
        let arr: [u8; 8] = self.bytes.as_slice().try_into().ok()?;
        Some(u64::from_le_bytes(arr))
    }

    /// UTF-16LE strings embedded in the data, scanning at most the first [`BINARY_UTF16_SCAN_MAX`] bytes.
    ///
    /// Meant for the "binary" carrier of the reference index (`REG_BINARY`, `REG_NONE` and unknown types),
    /// but works on any type. Both byte alignments are scanned. A run is a sequence of at least
    /// [`BINARY_UTF16_MIN_CHARS`] non-control characters; lone surrogates and `U+xx00` characters (above
    /// `U+00FF`, the pattern of ASCII text read at the wrong alignment) end a run. A run may start with a
    /// few junk characters decoded from the bytes before the text, so match anchors by substring. Results
    /// are in order of byte offset, without duplicates. `None` when the data is unknown.
    pub fn binary_utf16_strings(&self) -> Option<Vec<String>> {
        if self.data_unknown {
            return None;
        }
        let window = &self.bytes[..self.bytes.len().min(BINARY_UTF16_SCAN_MAX)];
        let mut found: Vec<(usize, String)> = Vec::new();
        for align in 0..2 {
            let units = bytes_to_units(window.get(align..).unwrap_or(&[]));
            let mut run = String::new();
            let mut run_chars = 0usize;
            let mut start = 0usize;
            let mut flush = |run: &mut String, run_chars: &mut usize, start: usize| {
                if *run_chars >= BINARY_UTF16_MIN_CHARS {
                    found.push((start * 2 + align, std::mem::take(run)));
                } else {
                    run.clear();
                }
                *run_chars = 0;
            };
            let mut i = 0;
            while i < units.len() {
                let u = units[i];
                let (decoded, width) = match u {
                    0xD800..=0xDBFF => match units.get(i + 1) {
                        Some(&lo @ 0xDC00..=0xDFFF) => (
                            char::from_u32(
                                0x10000
                                    + ((u32::from(u) - 0xD800) << 10)
                                    + (u32::from(lo) - 0xDC00),
                            ),
                            2,
                        ),
                        _ => (None, 1),
                    },
                    0xDC00..=0xDFFF => (None, 1),
                    _ if u > 0xFF && u & 0xFF == 0 => (None, 1),
                    _ => (char::from_u32(u32::from(u)), 1),
                };
                match decoded {
                    Some(c) if !c.is_control() => {
                        if run_chars == 0 {
                            start = i;
                        }
                        run.push(c);
                        run_chars += 1;
                    }
                    _ => flush(&mut run, &mut run_chars, start),
                }
                i += width;
            }
            flush(&mut run, &mut run_chars, start);
        }
        found.sort_by_key(|(off, _)| *off);
        let mut out: Vec<String> = Vec::new();
        for (_, s) in found {
            if !out.contains(&s) {
                out.push(s);
            }
        }
        Some(out)
    }
}

/// One named registry value. The default value has the empty name `""`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegValue {
    /// The value name; `""` for the default value.
    pub name: String,
    /// The value's data.
    pub data: RegData,
}

/// Metadata of one registry key (`RegQueryInfoKeyW` plus link and owner facts).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyInfo {
    /// The key's LastWriteTime.
    pub lwt: FileTime,
    /// Number of values.
    pub n_values: u32,
    /// Number of subkeys.
    pub n_subkeys: u32,
    /// The key is a symbolic link (`REG_OPTION_CREATE_LINK`); it is reported, never followed.
    pub is_link: bool,
    /// The link's `SymbolicLinkValue`, when it is a link and the target is readable.
    pub link_target: Option<String>,
    /// Whether TrustedInstaller owns the key or holds a write ACE on it; `None` when the source cannot
    /// tell (rig snapshots do not record it).
    pub ti_owned: Option<bool>,
}

// ---------------------------------------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------------------------------------

/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// `FILE_ATTRIBUTE_ARCHIVE`.
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// The three file times; any of them may be unknown (rig snapshots record only the write time).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileTimes {
    /// Creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<FileTime>,
    /// Last write time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<FileTime>,
    /// Last access time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed: Option<FileTime>,
}

/// Metadata of a file or directory, read without following reparse points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileMeta {
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// `FILE_ATTRIBUTE_*` bits. Directories always carry [`FILE_ATTRIBUTE_DIRECTORY`].
    pub attrs: u32,
    /// File times.
    pub times: FileTimes,
    /// The reparse tag, 0 when the object is not a reparse point.
    pub reparse_tag: u32,
    /// The 128-bit `FileIdInfo` id, when the source has it.
    pub file_id: Option<u128>,
}

impl FileMeta {
    /// Whether the object is a directory.
    pub fn is_dir(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// Whether the object is a reparse point (junction, symlink, mount point, cloud placeholder, …).
    pub fn is_reparse_point(&self) -> bool {
        self.reparse_tag != 0 || self.attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DirEntry {
    /// The entry's name (one path segment).
    pub name: String,
    /// The entry's metadata.
    pub meta: FileMeta,
}

/// The `VS_VERSIONINFO` strings of an executable (first translation).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionInfo {
    /// `CompanyName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company_name: Option<String>,
    /// `ProductName`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    /// `FileDescription`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_description: Option<String>,
    /// `OriginalFilename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    /// `FileVersion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    /// `ProductVersion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
}

/// What a `.lnk` file says, read without resolving it (`SLGP_RAWPATH`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShortcutInfo {
    /// The raw target path (environment variables unexpanded); `None` for a link to a shell item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_path: Option<String>,
    /// The arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    /// The working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// `System.AppUserModel.ID` of the link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aumid: Option<String>,
}

/// The volume a path lives on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VolumeInfo {
    /// The volume serial number, when known.
    pub serial: Option<u32>,
    /// A fixed (non-removable, non-network) drive.
    pub fixed: bool,
    /// The filesystem name, e.g. `NTFS`, `ReFS`, `FAT32`.
    pub fs: String,
}

impl VolumeInfo {
    /// Whether "file not found" on this volume proves absence: a fixed NTFS or ReFS volume. On anything
    /// else (removable, network, FAT) a missing path is [`ExistsState::Unknown`].
    pub fn proves_absence(&self) -> bool {
        self.fixed && (self.fs.eq_ignore_ascii_case("NTFS") || self.fs.eq_ignore_ascii_case("ReFS"))
    }
}

// ---------------------------------------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------------------------------------

/// One user profile from `ProfileList`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileInfo {
    /// The user's SID.
    pub sid: String,
    /// The profile directory (`ProfileImagePath`, expanded).
    pub path: String,
}

/// A known folder (`KNOWNFOLDERID`) of the interactive user or the machine. Names follow the `FOLDERID_`
/// suffixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KnownFolder {
    /// `%WINDIR%`.
    Windows,
    /// `%WINDIR%\System32`.
    System,
    /// `%WINDIR%\SysWOW64`.
    SystemX86,
    /// `%WINDIR%\Fonts`.
    Fonts,
    /// `C:\Program Files`.
    ProgramFiles,
    /// `C:\Program Files (x86)`.
    ProgramFilesX86,
    /// `C:\Program Files\Common Files`.
    ProgramFilesCommon,
    /// `C:\Program Files (x86)\Common Files`.
    ProgramFilesCommonX86,
    /// `C:\ProgramData`.
    ProgramData,
    /// `C:\Users\Public`.
    Public,
    /// `C:\Users\Public\Desktop`.
    PublicDesktop,
    /// `ProgramData\Microsoft\Windows\Start Menu`.
    CommonStartMenu,
    /// `ProgramData\Microsoft\Windows\Start Menu\Programs`.
    CommonPrograms,
    /// `ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`.
    CommonStartup,
    /// The user's profile directory.
    Profile,
    /// `%APPDATA%`.
    RoamingAppData,
    /// `%LOCALAPPDATA%`.
    LocalAppData,
    /// `%USERPROFILE%\AppData\LocalLow`.
    LocalAppDataLow,
    /// `%LOCALAPPDATA%\Programs`.
    UserProgramFiles,
    /// The user's desktop.
    Desktop,
    /// The user's documents.
    Documents,
    /// The user's downloads.
    Downloads,
    /// The user's Start Menu.
    StartMenu,
    /// The user's Start Menu `Programs`.
    Programs,
    /// The user's `Startup` folder.
    Startup,
    /// The user's `Templates`.
    Templates,
    /// The user's `SendTo`.
    SendTo,
}

impl KnownFolder {
    /// Every known folder, in declaration order.
    pub const ALL: [KnownFolder; 27] = [
        KnownFolder::Windows,
        KnownFolder::System,
        KnownFolder::SystemX86,
        KnownFolder::Fonts,
        KnownFolder::ProgramFiles,
        KnownFolder::ProgramFilesX86,
        KnownFolder::ProgramFilesCommon,
        KnownFolder::ProgramFilesCommonX86,
        KnownFolder::ProgramData,
        KnownFolder::Public,
        KnownFolder::PublicDesktop,
        KnownFolder::CommonStartMenu,
        KnownFolder::CommonPrograms,
        KnownFolder::CommonStartup,
        KnownFolder::Profile,
        KnownFolder::RoamingAppData,
        KnownFolder::LocalAppData,
        KnownFolder::LocalAppDataLow,
        KnownFolder::UserProgramFiles,
        KnownFolder::Desktop,
        KnownFolder::Documents,
        KnownFolder::Downloads,
        KnownFolder::StartMenu,
        KnownFolder::Programs,
        KnownFolder::Startup,
        KnownFolder::Templates,
        KnownFolder::SendTo,
    ];

    /// Whether the folder belongs to one user's profile (as opposed to the machine).
    pub fn is_per_user(self) -> bool {
        matches!(
            self,
            KnownFolder::Profile
                | KnownFolder::RoamingAppData
                | KnownFolder::LocalAppData
                | KnownFolder::LocalAppDataLow
                | KnownFolder::UserProgramFiles
                | KnownFolder::Desktop
                | KnownFolder::Documents
                | KnownFolder::Downloads
                | KnownFolder::StartMenu
                | KnownFolder::Programs
                | KnownFolder::Startup
                | KnownFolder::Templates
                | KnownFolder::SendTo
        )
    }
}

impl fmt::Display for KnownFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A running process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process id.
    pub pid: u32,
    /// Parent process id, when known.
    #[serde(default)]
    pub ppid: Option<u32>,
    /// Image name, e.g. `Code.exe`.
    pub name: String,
    /// Full image path, when readable.
    #[serde(default)]
    pub path: Option<String>,
    /// Start time, when known.
    #[serde(default)]
    pub start: Option<FileTime>,
    /// Session id, when known.
    #[serde(default)]
    pub session: Option<u32>,
    /// Command line, when readable.
    #[serde(default)]
    pub cmd: Option<String>,
}

/// An installed MSI product (`MsiEnumProductsExW` + `MsiGetProductInfoExW`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MsiProduct {
    /// The ProductCode, `{GUID}` in upper case.
    pub code: String,
    /// The installation context.
    pub context: MsiContext,
    /// The SID of the user for per-user contexts (`S-1-5-18` for machine in some sources).
    #[serde(default)]
    pub user_sid: Option<String>,
    /// `ProductName`.
    #[serde(default)]
    pub name: Option<String>,
    /// `VersionString`.
    #[serde(default)]
    pub version: Option<String>,
    /// `Publisher`.
    #[serde(default)]
    pub publisher: Option<String>,
    /// `InstallLocation`.
    #[serde(default)]
    pub install_location: Option<String>,
    /// `LocalPackage` (the cached `.msi`).
    #[serde(default)]
    pub local_package: Option<String>,
    /// `InstallDate` (`YYYYMMDD`).
    #[serde(default)]
    pub install_date: Option<String>,
}

/// An `INSTALLSTATE` as `MsiQueryProductStateW` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MsiProductState {
    /// `INSTALLSTATE_UNKNOWN` (-1): the product is neither advertised nor installed.
    Unknown,
    /// `INSTALLSTATE_ADVERTISED` (1).
    Advertised,
    /// `INSTALLSTATE_ABSENT` (2): installed for a different user.
    Absent,
    /// `INSTALLSTATE_DEFAULT` (5): installed for the current user.
    Default,
    /// Any other raw state.
    Other(i32),
}

impl MsiProductState {
    /// From the raw `INSTALLSTATE` number.
    pub fn from_raw(v: i32) -> Self {
        match v {
            -1 => Self::Unknown,
            1 => Self::Advertised,
            2 => Self::Absent,
            5 => Self::Default,
            other => Self::Other(other),
        }
    }

    /// The raw `INSTALLSTATE` number.
    pub fn raw(self) -> i32 {
        match self {
            Self::Unknown => -1,
            Self::Advertised => 1,
            Self::Absent => 2,
            Self::Default => 5,
            Self::Other(v) => v,
        }
    }

    /// Whether the state is `INSTALLSTATE_UNKNOWN`.
    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }
}

/// The state of one product in one context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MsiContextState {
    /// The context queried.
    pub context: MsiContext,
    /// The state there.
    pub state: MsiProductState,
}

/// How an AppX/MSIX package is signed (`Package.SignatureKind`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackageSignatureKind {
    /// The source did not say (rig lists do not record it).
    #[default]
    Unknown,
    /// Unsigned.
    None,
    /// Developer-signed.
    Developer,
    /// Enterprise-signed.
    Enterprise,
    /// Store-signed.
    Store,
    /// System (inbox) package.
    System,
}

/// One registered AppX/MSIX package (APPX-MIN: read only, for the sparse-package link).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageInfo {
    /// `PackageFullName`.
    pub full_name: String,
    /// `PackageFamilyName`.
    pub family: String,
    /// `InstalledLocation`.
    #[serde(default)]
    pub install_location: Option<String>,
    /// `EffectiveExternalPath` of a sparse package (its external location).
    #[serde(default)]
    pub external_location: Option<String>,
    /// The manifest allows external content (a sparse package), even when no external path was read.
    #[serde(default)]
    pub sparse: bool,
    /// SIDs of the users the package is registered for.
    #[serde(default)]
    pub users: Vec<String>,
    /// A framework package.
    #[serde(default)]
    pub is_framework: bool,
    /// A resource package.
    #[serde(default)]
    pub is_resource: bool,
    /// The signature kind.
    #[serde(default)]
    pub signature_kind: PackageSignatureKind,
}

impl PackageInfo {
    /// A sparse package: the flag is set or an external location is known.
    pub fn is_sparse(&self) -> bool {
        self.sparse || self.external_location.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_value_and_strings() {
        let d = RegData::from_sz("hello");
        assert_eq!(d.bytes.len(), 12);
        assert_eq!(d.len, 12);
        assert_eq!(d.sz().as_deref(), Some("hello"));
        assert_eq!(d.string().as_deref(), Some("hello"));
        assert_eq!(d.expand_sz(), None);
        assert_eq!(d.dword(), None);
        let e = RegData::from_expand_sz("%ProgramFiles%\\x");
        assert_eq!(e.expand_sz().as_deref(), Some("%ProgramFiles%\\x"));
        assert_eq!(e.sz(), None);
        let l = RegData::from_link("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes");
        assert_eq!(l.bytes.len(), 2 * 34);
        assert_eq!(
            l.link_target().as_deref(),
            Some("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes")
        );
    }

    #[test]
    fn multi_sz_segmentation() {
        let d = RegData::from_multi_sz(&["a", "bc", "def"]);
        assert_eq!(d.multi_sz().unwrap(), vec!["a", "bc", "def"]);
        // Interior empty strings are kept, trailing terminators dropped.
        let raw: Vec<u8> = "x\0\0y\0\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let d = RegData::new(REG_MULTI_SZ, raw);
        assert_eq!(d.multi_sz().unwrap(), vec!["x", "", "y"]);
        // No terminator at all.
        let raw: Vec<u8> = "p\0q".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(
            RegData::new(REG_MULTI_SZ, raw).multi_sz().unwrap(),
            vec!["p", "q"]
        );
        assert_eq!(
            RegData::from_multi_sz::<&str>(&[]).multi_sz().unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(RegData::from_sz("a").multi_sz(), None);
    }

    #[test]
    fn numbers() {
        assert_eq!(RegData::from_dword(7).dword(), Some(7));
        assert_eq!(RegData::from_qword(1 << 40).qword(), Some(1 << 40));
        assert_eq!(
            RegData::new(REG_DWORD_BIG_ENDIAN, vec![0, 0, 1, 0]).dword(),
            Some(256)
        );
        assert_eq!(RegData::new(REG_DWORD, vec![1, 2]).dword(), None);
        assert_eq!(RegData::from_qword(5).dword(), None);
    }

    #[test]
    fn unknown_data_accessors_are_none() {
        let d = RegData::unknown(REG_SZ, 20);
        assert_eq!(d.sz(), None);
        assert_eq!(d.multi_sz(), None);
        assert_eq!(d.binary_utf16_strings(), None);
        assert!(!d.is_complete());
        let mut q = RegData::from_qword(3);
        q.truncated = true;
        assert_eq!(q.qword(), None);
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn binary_utf16_extraction_and_bound() {
        let mut blob = vec![1, 2, 3, 0xff];
        blob.extend(utf16("C:\\Program Files\\App"));
        blob.extend([0, 0, 9, 9]);
        // Odd alignment.
        blob.push(7);
        blob.extend(utf16("Odd one"));
        blob.extend([0, 0]);
        let found = RegData::from_binary(blob).binary_utf16_strings().unwrap();
        // Bytes before the text may decode as a junk prefix; anchors are matched by substring.
        assert!(
            found.iter().any(|s| s.ends_with("C:\\Program Files\\App")),
            "{found:?}"
        );
        assert!(found.iter().any(|s| s.ends_with("Odd one")), "{found:?}");
        // Misaligned ASCII (U+xx00 characters) is not reported.
        assert!(
            !found.iter().any(|s| s
                .chars()
                .any(|c| (c as u32) > 0xff && (c as u32) & 0xff == 0)),
            "{found:?}"
        );
        // Short runs are ignored.
        let found = RegData::from_binary(utf16("abc"))
            .binary_utf16_strings()
            .unwrap();
        assert!(found.is_empty());

        // A string that starts inside the 4 KB window is cut at the window; one after it is not seen.
        let mut big = vec![0u8; BINARY_UTF16_SCAN_MAX - 10];
        big.extend(utf16("ABCDEFGHIJ"));
        let tail_at = big.len();
        big.extend([0, 0]);
        big.extend(utf16("BeyondTheBound"));
        assert!(tail_at > BINARY_UTF16_SCAN_MAX);
        let found = RegData::from_binary(big).binary_utf16_strings().unwrap();
        assert!(found.contains(&"ABCDE".to_string()), "{found:?}");
        assert!(!found.iter().any(|s| s.contains("Beyond")), "{found:?}");
    }

    #[test]
    fn found_helper() {
        let r: SourceResult<u8> = Err(SourceError::NotFound);
        assert_eq!(r.found(), Ok(None));
        let r: SourceResult<u8> = Err(SourceError::NotCaptured);
        assert_eq!(r.found(), Err(SourceError::NotCaptured));
        let r: SourceResult<u8> = Ok(3);
        assert_eq!(r.found(), Ok(Some(3)));
    }

    #[test]
    fn msi_state_raw_round_trip() {
        for v in [-1, 1, 2, 5, 3, -2] {
            assert_eq!(MsiProductState::from_raw(v).raw(), v);
        }
        assert!(MsiProductState::from_raw(-1).is_unknown());
    }

    #[test]
    fn volume_absence_rule() {
        let v = |fixed, fs: &str| VolumeInfo {
            serial: None,
            fixed,
            fs: fs.into(),
        };
        assert!(v(true, "NTFS").proves_absence());
        assert!(v(true, "ReFS").proves_absence());
        assert!(!v(false, "NTFS").proves_absence());
        assert!(!v(true, "FAT32").proves_absence());
    }

    #[test]
    fn file_meta_flags() {
        let m = FileMeta {
            size: 0,
            attrs: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            times: FileTimes::default(),
            reparse_tag: 0xA000_0003,
            file_id: Some(u128::MAX - 1),
        };
        assert!(m.is_dir() && m.is_reparse_point());
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<FileMeta>(&json).unwrap(), m);
    }
}
